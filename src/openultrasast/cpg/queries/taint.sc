// Taint reachability for one flow family (model-grounded-detection Req 6.1).
//
// The question this answers is the one our flat IR could not: does an untrusted source reach the labeled sink
// *through resolved dataflow*, and is there a sanitizer on that path. `reachableByFlows` walks the PDG, so a
// value bound several statements upstream is found:
//
//     cmd  = request.args["cmd"]        request.args["cmd"] -> cmd -> "echo " + cmd -> full
//     full = "echo " + cmd
//     os.system(full)
//
// That three-hop chain is exactly the one-hop limit which held our measured entailment at 2.2%.
//
// Two things here are easy to get backwards and were, first time round:
//   * the sink is the call's ARGUMENTS, not the call node -- data flows into arguments;
//   * `reachableByFlows` is called ON the sink WITH the source, not the other way about.
//
// Parameters (comma-separated where plural):
//   cpgFile, sources, sinks, sanitizers (optional), function (optional: restrict to this method AND any
//     closure lexically nested inside it -- see `nestedInLabeled`),
//   parameterSources ("true" to treat the labeled function's parameters as untrusted -- see below),
//   file (optional: restrict sinks to this source file),
//   callDepth (optional: how many call-graph levels below the labeled method may hold a sink),
//   boundedSinks (optional: sinks whose danger is a LENGTH, which a dominating bound discharges)
//
// `file` is what makes a region with no enclosing function askable at all. Without it such a region sends
//   function="" and matches every sink in the repository, and the driver attributes that whole answer to
//   whichever region asked. Scoping by file also stops a named function matching a same-named function in
//   another module, which a corpus of one-file excerpts could never surface.
//
// Output: a fenced JSON array of {sink, sinkLine, sinkMethod, source, sanitized, length}. The fence exists
// because Joern prints a banner, pass logs and a prompt around whatever a script emits.

// BATCHED. `requests` is a JSON object of {id: {sources, sinks, sanitizers, function, parameterSources}} and
// the output is {id: [row, ...]}. One invocation answers a whole scan's questions, because the JVM start
// (~30s) dwarfs the queries themselves once the CPG is loaded -- one call per region per family put a
// ten-line file at four minutes and a thousand regions at roughly fifty hours.
//
// The single-request form is kept below it: the pair harnesses and every measurement committed so far use it,
// and changing their call shape would silently invalidate comparisons against those artifacts.

@main def exec(
    cpgFile: String,
    sources: String = "",
    sinks: String = "",
    sanitizers: String = "",
    function: String = "",
    file: String = "",
    callDepth: String = "0",
    boundedSinks: String = "",
    parameterSources: String = "false",
    fieldSources: String = "true",
    evidenceOnly: String = "false",
    hookCallbacks: String = "",
    dispatchApply: String = "",
    requests: String = "",
    requestsFile: String = ""
) = {
  importCpg(cpgFile)

  // The batch arrives as a FILE. A single command-line argument is capped at 128KB on Linux and a
  // repository's requests are megabytes, so passing them as `--param requests=` failed with E2BIG and the
  // driver read the empty result as "no rows". `requests` is kept for the single-request forms and the tests.
  val requestsJson =
    if (requestsFile.nonEmpty) scala.io.Source.fromFile(requestsFile).mkString
    else requests

  def split(raw: String): List[String] = raw.split(",").map(_.trim).filter(_.nonEmpty).toList

  // Per-family answers that do not depend on the region, kept across the whole batch.
  val familyInRepoMemo = scala.collection.mutable.Map.empty[String, Boolean]
  val sinkCandidatesMemo = scala.collection.mutable.Map.empty[String, List[io.shiftleft.codepropertygraph.generated.nodes.Call]]
  val reachableMemo = scala.collection.mutable.Map.empty[(String, String, Int), Set[String]]
  val methodSourceMemo = scala.collection.mutable.Map.empty[String, Boolean]

  def rowsFor(
      sourcesS: String,
      sinksS: String,
      sanitizersS: String,
      hookCallbacksS: String,
      dispatchApplyS: String,
      functionS: String,
      paramSrc: String,
      fieldSrc: String,
      evidenceS: String,
      fileS: String,
      depthS: String,
      boundedS: String
  ): List[ujson.Obj] = {

  // Word-boundary matching, never substring. `resolveUrl` contains `resolve`, so a bare-substring sanitizer
  // test marked the VULNERABLE flow sanitized and the verdict fell back to a captured `res` that names no
  // attacker input. Same bug class as the dominance query's guard matching; fixed in both.
  // The boundary only applies where there IS a word character to bound: a token like `input(` ends in `(`,
  // and an unconditional lookahead would make it unmatchable in `input(x)`.
  def boundedPattern(token: String): java.util.regex.Pattern = {
    val before = if (token.headOption.exists(c => c.isLetterOrDigit || c == '_')) "(?<![A-Za-z0-9_])" else ""
    val after = if (token.lastOption.exists(c => c.isLetterOrDigit || c == '_')) "(?![A-Za-z0-9_])" else ""
    java.util.regex.Pattern.compile(before + java.util.regex.Pattern.quote(token) + after)
  }

  def mentionsToken(code: String, tokens: List[String]): Boolean =
    tokens.exists(t => boundedPattern(t).matcher(code).find())

  val sourcePatterns = split(sourcesS)
  val sinkNames      = split(sinksS)
  val sanitizerNames = split(sanitizersS)
  val boundedNames   = split(boundedS)

  // A relational comparison against an integer literal: `len > 250`, `n <= sizeof(buf)`. Equality and null
  // checks are deliberately excluded -- `if (buf)` and `p == NULL` govern whether the sink RUNS, not how
  // much it copies, and counting them would discharge every guarded-against-null overflow there is.
  val boundShape = java.util.regex.Pattern.compile("(?:<=|>=|<|>)\\s*[0-9]+|[0-9]+\\s*(?:<=|>=|<|>)")
  val function       = functionS
  val parameterSources = paramSrc

  // A source is any call whose code contains one of the patterns. Matching on `code` rather than a method
  // name keeps `request.args["x"]` (an indexAccess over a fieldAccess) and `req.body.name` both reachable
  // without a per-framework rule for each.
  // Framework sources: a call whose code contains one of the patterns. Matching on `code` rather than a
  // method name keeps `request.args["x"]` (an indexAccess over a fieldAccess) and `req.body.name` both
  // reachable without a per-framework rule for each.
  def frameworkSources = cpg.call.filter(c => sourcePatterns.exists(p => c.code.contains(p)))

  // The labeled methods, and the region they lexically own. A closure defined inside the labeled function --
  // the callback passed to `fs.stat`, say -- has its own synthetic method (`<lambda>0`) whose astParentFullName
  // is empty, so nesting is decided by line-range containment within the same file, which is reliable.
  // Resolved by name AND file when a file is given: `get_user` exists in more than one module of a real
  // repository, and a corpus of one-file excerpts could never show that.
  lazy val labeledMethods = {
    val byName = if (function.isEmpty) List.empty else cpg.method.nameExact(function).l
    if (fileS.isEmpty) byName else byName.filter(_.filename.endsWith(fileS))
  }

  // The methods a sink may live in. Lexical nesting alone stops at the function boundary, and a real
  // injection bug rarely respects it: VAmPI's is a request parameter reaching a handler, passed to a method
  // in another module, interpolated there and executed. `reachableByFlows` already follows calls; what did
  // not was the QUESTION -- sinks were filtered to the labeled function's own body, so the flow had no sink
  // to end at and the engine was silent.
  //
  // Bounded by `callDepth`, because "every method transitively reachable from an entry point" is most of a
  // repository, and an unbounded question is how this becomes slow again.
  val depth = scala.util.Try(depthS.toInt).getOrElse(0)
  lazy val reachableMethods: Set[String] = reachableMemo.getOrElseUpdate((function, fileS, depth), computeReachable)

  def computeReachable: Set[String] =
    if (depth <= 0 || labeledMethods.isEmpty) Set.empty
    else {
      var frontier = labeledMethods.toSet
      var seen     = frontier.map(_.fullName)
      var level    = 0
      while (level < depth && frontier.nonEmpty) {
        val next = frontier.flatMap(_.callee.l).filterNot(m => seen.contains(m.fullName))
        seen = seen ++ next.map(_.fullName)
        frontier = next
        level += 1
      }
      seen
    }

  // A module body spans its whole file, so line-range containment would make `<module>` the parent of every
  // function in it -- and a module-scope region would then report every handler's sinks a second time. The
  // module region exists to cover the code that is in NO function, so its membership is direct.
  val moduleScope = function == "<module>"

  def nestedInLabeled(m: io.shiftleft.codepropertygraph.generated.nodes.Method): Boolean =
    if (moduleScope) m.name == function
    else
      labeledMethods.exists { lm =>
        m.name == function || (
          m.filename == lm.filename &&
          m.lineNumber.getOrElse(-1) >= lm.lineNumber.getOrElse(0) &&
          m.lineNumberEnd.getOrElse(-1) <= lm.lineNumberEnd.getOrElse(Int.MaxValue)
        )
      }

  // Parameter sources: the labeled function's OWN parameters, never a nested closure's. In a function-level
  // pair the function boundary IS the trust boundary -- the corpus is built so the labeled function's inputs
  // are attacker-controlled -- and 39 of the injection slice's 50 pairs carry no framework token at all. Our
  // flat-IR baseline counted these (`source_kinds: ["parameter"]`), so the comparison is only like-for-like
  // with them on. Scoping matters as much as enabling: a callback's own parameters (`err`, `stats`) are not
  // attacker input, and counting them produced flows like `res -> readFileSync` that name no real source.
  // Off by default: outside a labeled function, treating every parameter as untrusted is not sound.
  //
  // The RECEIVER is excluded, and only because the field half below makes that safe. `$this` is a parameter
  // in the CPG -- index 0 of every PHP method -- and counting it means every method that reads any field
  // reaches every sink: 11 of 15 entailed findings on one PMPro class were `this -> $wpdb->...`, one of them
  // surviving into 2.9.8 at a query whose every fragment is `esc_sql`-wrapped.
  //
  // Excluding it was TRIED FIRST and reverted, because on its own it loses CVE-2023-6559: MW WP Form's
  // `_delete_files()` takes no parameters at all and its attacker-controlled path arrives as
  // `$this->attachments`. Trading a verified CVE for findings merely suspected of being false is the wrong
  // trade, and deleting the receiver removes the symptom by removing the evidence.
  //
  // With `fieldSourceNodes` below, that path is carried by the field it actually travels through, so the
  // receiver no longer has to stand in for it. The order matters: this line is only correct because of the
  // one after it.
  def parameterNodes =
    if (parameterSources != "true") Iterator.empty
    else if (function.isEmpty) cpg.method.parameter.filterNot(_.name == "this").iterator
    else cpg.method.nameExact(function).parameter.filterNot(_.name == "this").iterator

  // The region this request is about, as a predicate on the method. Named rather than inlined because the
  // field sources have to be scoped to exactly the same place as the sinks, and a second copy of these
  // three branches is precisely the drift this file has been bitten by before.
  def inScope(m: io.shiftleft.codepropertygraph.generated.nodes.Method): Boolean =
    if (function.isEmpty) {
      // A region with no enclosing function: the file IS the scope.
      fileS.isEmpty || m.filename.endsWith(fileS)
    } else if (depth > 0) {
      // Following the call graph means leaving the region's file on purpose, so the file filter would
      // contradict the point. The reachable set is the scope, and the row reports where the sink landed.
      nestedInLabeled(m) || reachableMethods.contains(m.fullName)
    } else {
      (fileS.isEmpty || m.filename.endsWith(fileS)) && nestedInLabeled(m)
    }

  // ---- the field half of the two-stage join (task 5.11) ---------------------------------------------
  //
  // `_delete_files()` takes no parameters at all. Its attacker-controlled path arrives as a FIELD, written
  // by one method and read back by another:
  //
  //     public function __construct( ..., array $attachments = array() )   // a parameter
  //         $this->attachments = $attachments;                             // half one ends here
  //     protected function _delete_files()
  //         foreach ( $this->attachments as $file )                        // half two starts here
  //             unlink( $file );                                           // CVE-2023-6559
  //
  // Both halves are already in the graph: parameter to assignment inside one method, field read to sink
  // inside another. Only the JOIN between them is missing, and the key it joins on is the literal
  // `$this->attachments`, written identically at both ends. So this is a second question asked with the
  // query that already exists, not an edge a frontend has to invent.
  //
  // The alternative is making `$this` itself a source. That finds this CVE and eleven false positives with
  // it on one PMPro class, because every method that reads any field then reaches every sink. A field name
  // is the precision, and it costs one string comparison.
  //
  // Scoped three ways, so a field name common to every class ever written cannot become a wormhole:
  //   * only fields the sink scope actually READS are considered;
  //   * only assignments in the SAME FILE count;
  //   * the assignment's right-hand side must itself be reachable from a source -- which is the whole claim.
  val FIELD_ACCESS = "<operator>.fieldAccess"
  val ASSIGNMENT   = "<operator>.assignment"

  // Memoized per FIELD, not per file, because the expensive part is one flow query per candidate assignment
  // and only the fields some region actually reads are worth asking about. A batch asks about one file many
  // times over -- 205 requests across 41 regions of one class -- so without a memo this runs hundreds of
  // times over the same assignments.
  val methodsByFile  = scala.collection.mutable.Map.empty[String, List[io.shiftleft.codepropertygraph.generated.nodes.Method]]
  val seedsByFile    = scala.collection.mutable.Map.empty[String, List[io.shiftleft.codepropertygraph.generated.nodes.CfgNode]]
  val fieldTaintMemo = scala.collection.mutable.Map.empty[(String, String), Boolean]

  def methodsIn(fileName: String) =
    methodsByFile.getOrElseUpdate(fileName, cpg.method.filter(m => fileName.isEmpty || m.filename.endsWith(fileName)).l)

  // Framework sources are untrusted wherever they appear. Parameters are untrusted only where the caller has
  // said this region is an entry point -- the same contract `parameterNodes` carries, and for the same
  // reason: an arbitrary helper's parameters carry whatever its caller happened to have.
  def seedsIn(fileName: String) =
    seedsByFile.getOrElseUpdate(
      fileName, {
        val methods = methodsIn(fileName)
        val framework: List[io.shiftleft.codepropertygraph.generated.nodes.CfgNode] =
          methods.flatMap(_.ast.isCall.filter(c => sourcePatterns.exists(p => c.code.contains(p))).l)
        val params: List[io.shiftleft.codepropertygraph.generated.nodes.CfgNode] =
          if (parameterSources == "true") methods.flatMap(_.parameter.l) else Nil
        framework ++ params
      }
    )

  def fieldIsTainted(fileName: String, fieldCode: String): Boolean =
    fieldTaintMemo.getOrElseUpdate(
      (fileName, fieldCode), {
        val seeds = seedsIn(fileName)
        if (seeds.isEmpty) false
        else
          methodsIn(fileName).flatMap(_.ast.isCall.nameExact(ASSIGNMENT).l).exists { assignment =>
            val args = assignment.argument.l
            args.size >= 2 && (args.head match {
              case target: io.shiftleft.codepropertygraph.generated.nodes.Call
                  if target.name == FIELD_ACCESS && target.code.trim == fieldCode =>
                // The summary must carry the SANITIZATION status of the half it summarises, not merely its
                // reachability. Asking only "does a source reach this assignment" marks
                // `$this->sqlQuery = "..." . esc_sql($x) . "..."` tainted, and PMPro builds most of its
                // queries that way: the fixed side of its pair went from 1 finding to 13 without this,
                // which is the pair no longer separating at all.
                val flows = args(1).start.reachableByFlows(seeds.iterator).l
                flows.exists(f => !f.elements.map(_.code).l.exists(code => mentionsToken(code, sanitizerNames)))
              case _ => false
            })
          }
      }
    )

  // A read of a MEMBER of a tainted object is tainted too. WP Statistics assigns the whole request to
  // `$this->rest_hits` in one method and reads `$this->rest_hits->current_page_id` in another, so an exact
  // code match sees two unrelated strings where the source text says one is inside the other. Every prefix
  // that ends on a `->` boundary is checked, left to right.
  def taintedPrefixes(code: String, fileName: String): Boolean = {
    val parts = code.split("->").map(_.trim).filter(_.nonEmpty)
    if (parts.length < 2) false
    else (2 to parts.length).exists(n => fieldIsTainted(fileName, parts.take(n).mkString("->")))
  }

  // Off by request only, and defaulting to ON when the field is absent, so nothing about the shipped
  // behaviour depends on a caller remembering to set it. It exists so the join can be measured against
  // itself: a cost you cannot switch off is a cost you cannot attribute.
  def fieldSourceNodes =
    if (fieldSrc != "true") Iterator.empty
    else {
      val reads = cpg.call.nameExact(FIELD_ACCESS).filter(c => inScope(c.method)).l
      if (reads.isEmpty) Iterator.empty else reads.filter(r => taintedPrefixes(r.code.trim, fileS)).iterator
    }

  // ---- the hook half of the two-stage join (task 5.11) ----------------------------------------------
  //
  // WP Statistics' CVE-2022-25148 has a modelled source, a modelled sink and `esc_sql` as its fix, and is
  // invisible on both sides, because the only thing joining the two files is
  //
  //     add_filter('wp_statistics_current_page', array($this, 'set_current_page'));   // hits.php:43
  //     return apply_filters('wp_statistics_current_page', $current_page);            // pages.php:105
  //
  // Both ends name the callback with a STRING, and php2cpg drops the callback argument entirely -- the CPG
  // literally holds `add_filter("wp_statistics_current_page", )`. So the link CANNOT come from the graph at
  // any price, and it arrives instead as `hookCallbacks`, read out of the source text by
  // `mapping.php_hook_callbacks` where both ends are literals.
  //
  // The rule: an `apply_filters('H', ...)` call is a SOURCE when some callback registered for H returns
  // data that an unsanitized flow reached. That is the same question as the field half, against a different
  // key.
  // The registry's vocabulary arrives as a FACT, never as a constant here. `apply_filters` is WordPress's
  // name for this; Django signals, jQuery events and Symfony's dispatcher all have their own, and each is a
  // row in a semantic fact table rather than an edit to this query.
  val hookApply = split(dispatchApplyS).toSet

  val hookTable: Map[String, List[String]] =
    hookCallbacksS
      .split(";")
      .map(_.trim)
      .filter(_.nonEmpty)
      .flatMap { entry =>
        val at = entry.indexOf(':')
        if (at <= 0 || at == entry.length - 1) None else Some(entry.substring(0, at) -> entry.substring(at + 1))
      }
      .groupBy(_._1)
      .map { case (hook, pairs) => hook -> pairs.map(_._2).toList }

  def unquote(raw: String): String = {
    val t = raw.trim
    if (t.length >= 2 && ((t.head == '"' && t.last == '"') || (t.head == '\'' && t.last == '\''))) t.substring(1, t.length - 1) else t
  }

  // Half one's seeds are STRICTER than the field half's, and deliberately. A filter callback's own parameter
  // is the value being filtered, not request data, and the receiver is the object -- counting either makes
  // every registered callback "return tainted" and the join degenerates into the complete graph this design
  // exists to refuse. Only a real framework source, or a field already shown to hold one, counts.
  //
  // They are NOT scoped to the requesting file, which the field half is: a hook registry is global by
  // construction, `set_current_page` lives in one file and the `apply_filters` that calls it in another,
  // and the query returned nothing while they were. They ARE scoped to the CALLBACK's file. The first
  // version scoped them to nothing -- every field access in every method of the repository, each put through
  // the field join -- and on a 637-file plugin that step alone did not finish in 270 s, for a callback whose
  // sources are, by the join's own logic, the reads in its body and the assignments in its class. WP
  // Statistics is the case that has to survive: the callback and `$this->rest_hits = ...` share a file,
  // and only the sink is elsewhere. Task 5.13 has the numbers.
  def hookSeedsOf(callback: io.shiftleft.codepropertygraph.generated.nodes.Method) = {
    val framework: List[io.shiftleft.codepropertygraph.generated.nodes.CfgNode] =
      callback.ast.isCall.filter(c => sourcePatterns.exists(p => c.code.contains(p))).l
    val fields: List[io.shiftleft.codepropertygraph.generated.nodes.CfgNode] =
      callback.ast.isCall.nameExact(FIELD_ACCESS).l.filter(r => taintedPrefixes(r.code.trim, callback.filename))
    framework ++ fields
  }

  // Half one is asked PER ARRAY KEY, not per callback, and that distinction is the whole result.
  //
  // "Does an unsanitized value reach this callback's return" is true on BOTH sides of the WP Statistics
  // pair, because the fix escapes two of the three members and leaves the third alone:
  //
  //     vulnerable   $tmp["id"] = $this->rest_hits->current_page_id
  //     fixed        $tmp["id"] = esc_sql($this->rest_hits->current_page_id)
  //     both         $tmp["search_query"] = ... unescaped, and harmless where it is used
  //
  // A callback-level answer flags the fixed side exactly as readily as the vulnerable one, which is a leak
  // and not a detection. The key is a literal at both ends -- written `"id"` in the callback and `['id']`
  // at the sink -- so it joins the same way the hook name and the field name do. Third use of one idea.
  val INDEX_ACCESS = "<operator>.indexAccess"
  val hookKeysMemo = scala.collection.mutable.Map.empty[String, Set[String]]

  def keyOf(access: io.shiftleft.codepropertygraph.generated.nodes.Call): String =
    access.argument.l.lift(1).map(a => unquote(a.code)).getOrElse("")

  def taintedKeysOf(callback: String): Set[String] =
    hookKeysMemo.getOrElseUpdate(
      callback,
      cpg.method
        .nameExact(callback)
        .l
        .flatMap { method =>
          val seeds = hookSeedsOf(method)
          if (seeds.isEmpty) Nil
          else
            method.ast.isCall
              .nameExact(ASSIGNMENT)
              .l
              .flatMap { assignment =>
                val args = assignment.argument.l
                if (args.size < 2) None
                else
                  args.head match {
                    case target: io.shiftleft.codepropertygraph.generated.nodes.Call if target.name == INDEX_ACCESS =>
                      val key = keyOf(target)
                      if (key.isEmpty) None
                      else if (args(1).start.reachableByFlows(seeds.iterator).l.exists(f => !f.elements.l.exists(sanitizesHere)))
                        Some(key)
                      else None
                    case _ => None
                  }
              }
        }
        .toSet
    )

  def hookSourceNodes =
    if (hookTable.isEmpty || hookApply.isEmpty) Iterator.empty
    else {
      val applies = cpg.call.filter(c => hookApply.contains(c.name)).filter(c => inScope(c.method)).l
      if (applies.isEmpty) Iterator.empty
      else {
        val keys = applies.flatMap { call =>
          val hook = call.argument.l.headOption.map(a => unquote(a.code)).getOrElse("")
          hookTable.getOrElse(hook, Nil).flatMap(taintedKeysOf)
        }.toSet
        if (keys.isEmpty) Iterator.empty
        else
          cpg.call
            .nameExact(INDEX_ACCESS)
            .filter(c => inScope(c.method))
            .l
            .filter(access => keys.contains(keyOf(access)))
            // ...and actually derived from the filtered value, not merely sharing a key name with it.
            .filter(access => access.start.reachableBy(applies.iterator).nonEmpty)
            .iterator
      }
    }

  // Materialised ONCE per request, because every one of the four is a `def` that walks the graph --
  // `frameworkSources` scans every call in the repository, `hookSourceNodes` runs one `reachableBy` per
  // candidate index access -- and `sourceNodes` is consumed once per SINK. A file-scope region with 346 sinks
  // paid for 346 repository scans and 346 hook joins. Measured on ten real pmpro pairs at callDepth 1:
  // 16.5 s per request with the hook half off, past 54 s with it on, before this; see task 5.13.
  lazy val frameworkList = frameworkSources.l
  lazy val parameterList = parameterNodes.toList
  lazy val fieldList     = fieldSourceNodes.toList
  lazy val hookList      = hookSourceNodes.toList
  def sourceNodes = frameworkList.iterator ++ parameterList.iterator ++ fieldList.iterator ++ hookList.iterator

  // WHICH KIND of source a flow started from, reported per row so the driver can tell them apart.
  //
  // It has to be reported rather than guessed, because by the time a row reaches Python a hook source reads
  // as `$current_page["id"]` and a parameter reads as `$args` -- two identifiers, indistinguishable. The
  // driver treats parameter-sourced flows as a FALLBACK it discards whenever a real modelled source is also
  // present, which is right for parameters and wrong for these: on WP Statistics, seven sanitized
  // `$_SERVER["REQUEST_URI"]` flows displaced the unsanitized hook flow carrying CVE-2022-25148, and the
  // finding disappeared between the query and the verdict.
  lazy val frameworkIds = frameworkList.map(_.id).toSet
  lazy val fieldIds     = fieldList.map(_.id).toSet
  lazy val hookIds      = hookList.map(_.id).toSet

  def sourceKindOf(head: Option[io.shiftleft.codepropertygraph.generated.nodes.AstNode]): String =
    head match {
      case Some(node) if frameworkIds.contains(node.id) => "framework"
      case Some(node) if hookIds.contains(node.id)      => "hook"
      case Some(node) if fieldIds.contains(node.id)     => "field"
      case Some(_)                                      => "parameter"
      case None                                         => ""
    }

  // Whether there is anything to trace from at all. Asking `reachableByFlows` with an empty source list is
  // not merely wasted work: Joern answers it by logging "Attempting to determine flows from empty list of
  // sources." to STDOUT, which lands between the fence markers and makes the whole batch's JSON unparseable.
  // The driver then reports `query_failed` for every request in the batch, so one method with no sources
  // silently costs the answers for all two hundred of the others. Excluding the receiver made that common:
  // a method whose only parameter is `$this` now has none.
  lazy val hasSources = sourceNodes.hasNext

  // A sink call: matched by short name (`system`), by leading code (`os.system(...)`), or by resolved
  // full name (`os.py:<module>.system`), so both bare and dotted forms in the spec hit.
  //
  // Every clause is word-BOUNDED, and the unbounded `contains` that used to end this list is why: `fgets`
  // contains `gets`, so every bounded read in libpng matched the sink for the unbounded one, and all 26
  // entailed findings on that repository were the same false positive -- `*argv -> fgets(buf, 256, f)`,
  // which is the safe API being reported as the dangerous one. Third instance of this bug class here, after
  // the sanitizer that matched `resolve` inside `resolveUrl` and the discharger that matched `user` inside
  // `users`; the sink matcher had simply never been given the same treatment.
  def sinkMatches(c: io.shiftleft.codepropertygraph.generated.nodes.Call, n: String): Boolean =
    c.name == n || c.code.startsWith(n + "(") || mentionsToken(c.code, List(n)) || mentionsToken(c.methodFullName, List(n))

  // Does THIS path element cleanse the value flowing through it?
  //
  // The old test asked whether a sanitizer's name appeared anywhere in the element's source text, and that
  // is wrong on exactly the shape WordPress writes. WP Statistics' vulnerable query is one concatenation:
  //
  //     "... " . (array_key_exists(...) ? "AND `uri` = '" . esc_sql($page_uri) . "'" : "")
  //             . "AND `id` = {$current_page['id']}"
  //
  // `esc_sql` cleanses `$page_uri`. It does nothing whatsoever for `$current_page['id']`, which is the
  // injectable value and CVE-2022-25148 -- but both live in one expression, so the concatenation node's
  // code mentions `esc_sql` and the whole flow read as sanitized. A sibling's cleansing was being credited
  // to its neighbour.
  //
  // So the element must BE the cleansing, not merely contain a mention of one:
  //   * a call to the sanitizer -- by node name, or by its code opening with `name(`;
  //   * the sanitizer named as a string literal, which is how `array_map('esc_sql', $status)` applies it and
  //     is a form PMPro actually writes.
  def sanitizesHere(node: io.shiftleft.codepropertygraph.generated.nodes.AstNode): Boolean = {
    val code = node.code
    val byName = node match {
      case call: io.shiftleft.codepropertygraph.generated.nodes.Call => sanitizerNames.exists(n => call.name == n)
      case _                                                        => false
    }
    byName || sanitizerNames.exists(n => code.startsWith(n + "(") || code.contains("'" + n + "'") || code.contains("\"" + n + "\""))
  }

  // The candidate sink calls for a FAMILY do not depend on the region, and scanning every call in the graph
  // for each of 2,487 requests was a large share of what made a request cost seconds -- in evidence mode,
  // which asks for no dataflow at all, it alone took a query past an hour. Scanned once per sink list and
  // kept for the batch; the per-request work is the scope filter over that list.
  def sinkCalls =
    sinkCandidatesMemo
      .getOrElseUpdate(sinksS, cpg.call.filter(c => sinkNames.exists(n => sinkMatches(c, n))).l)
      .filter(c => inScope(c.method))

  // ---- EVIDENCE MODE: the same question without the dataflow (flow-aware-ranking, phase 0) --------------
  //
  // Tiering is the CPG query WITHOUT dataflow; arbitration is the query WITH it. Same graph, same facts, two
  // costs. This branch answers "what is in scope" -- which sink calls, what shape they take, whether a
  // cleansing call wraps THEIR argument, whether a source is local or reachable -- and returns before
  // `reachableByFlows` is ever called. Milliseconds per call, where a flow costs 6.63 seconds.
  //
  // Every field is stated in fact-table terms, so the vector means the same thing in every language the
  // graph can hold. A `summary` row is always emitted, even when there are no sinks, because "no sinks" is
  // tier 0 and must be distinguishable from "the query failed".
  if (evidenceS == "true") {
    // Whether a method holds a modelled source, memoised by full name across the batch: the same helper
    // is reachable from hundreds of regions, and re-walking its AST for each of them is what made a
    // no-dataflow query take minutes. `cpg.method.filter(...)` over every method per request was the
    // other half of that, replaced by a direct lookup of the reachable names.
    def methodHasSource(m: io.shiftleft.codepropertygraph.generated.nodes.Method): Boolean =
      methodSourceMemo.getOrElseUpdate(m.fullName, m.ast.isCall.exists(c => sourcePatterns.exists(p => c.code.contains(p))))
    val sinkList    = sinkCalls.l
    val sourceLocal = labeledMethods.exists(methodHasSource)
    val sourceNear  = depth > 0 && cpg.method.fullNameExact(reachableMethods.toSeq: _*).exists(methodHasSource)
    // Anywhere in the repository at all. Exact at every callDepth, and the cheapest cut there is: a family
    // with no sink anywhere cannot produce a flow for any region. Memoised on the sink list, because it is
    // the same answer for every request of one family and a repository-wide walk per request turned a
    // milliseconds-per-pair query into minutes.
    val familyInRepo = familyInRepoMemo.getOrElseUpdate(sinksS, cpg.call.exists(c => sinkNames.exists(n => sinkMatches(c, n))))
    val summary = ujson.Obj(
      "kind"         -> "summary",
      "sinks"        -> sinkList.size,
      "sourceLocal"  -> sourceLocal,
      "sourceNear"   -> sourceNear,
      "familyInRepo" -> familyInRepo
    )
    val perSink = sinkList.map { sink =>
      val realArgs = sink.argument.argumentIndexGt(0).l
      ujson.Obj(
        "kind"            -> "sink",
        "sink"            -> sink.code.take(200),
        "sinkLine"        -> sink.lineNumber.getOrElse(-1).toString,
        "sinkMethod"      -> sink.method.name,
        "sinkFile"        -> sink.method.filename.split("/").last,
        "sinkArity"       -> realArgs.size,
        "sinkArg0Literal" -> realArgs.headOption.map(a => a.isLiteral).getOrElse(false),
        // A sanitizer of this family is an ANCESTOR of an argument in the AST -- it wraps what flows in --
        // as opposed to merely appearing somewhere in the same function. This is the field a text scan
        // gets wrong, and the one that would have misranked CVE-2023-23488: `esc_sql` is in that function,
        // on a different statement.
        "cleansedOnCall"  -> sink.argument.ast.l.exists(node => sanitizesHere(node))
      )
    }
    return summary :: perSink
  }

  val rows = sinkCalls.l.flatMap { sink =>
    // Data flows into the arguments; asking the call node itself finds nothing.
    // `call.argument` includes the RECEIVER at argumentIndex 0 (`db` in `db.execute(...)`), so counting it
    // makes a one-argument interpolated call look like a two-argument bound one -- the exact inversion of the
    // test. Real arguments start at index 1.
    val realArgs = sink.argument.argumentIndexGt(0).l
    val flows    = if (hasSources) sink.argument.reachableByFlows(sourceNodes).l else Nil

    // The SHAPE of the sink call, which is what distinguishes a fix from a bug when the fix is a safe form
    // rather than a sanitizing call: `execute(sql, params)` binds where `execute(sql + x)` interpolates, and
    // `printf("literal", x)` is safe where `printf(userFmt)` is not. The taint path is identical in both, so
    // without these two fields the model entails a pair's fixed side exactly as readily as its vulnerable one.
    val arity       = realArgs.size
    val arg0Literal = realArgs.headOption.map(a => a.isLiteral).getOrElse(false)

    // Is there a bound on the data reaching this sink? Only asked of sinks whose CWE says the danger is a
    // length, and the bound must mention a name the sink actually uses -- an unrelated `i < 10` loop in the
    // same function discharges nothing.
    //
    // Scoped to the METHOD rather than to the sink's dominators, and that is deliberate. libpng guards
    // `strcpy(outname+len, ".png")` with `(len = strlen(inname)) > 250`, but the check sits on an else-if
    // chain whose sibling branch skips it entirely, and the protection is carried to the sink through an
    // `error` flag: `++error` in the guarded branch, `if (!error)` around the copy. So the bound does NOT
    // dominate the sink -- Joern is right about that -- and requiring dominance found nothing.
    //
    // Which is exactly why this lowers the rung instead of clearing the finding. A bound on this variable
    // somewhere in this function means the graph CANNOT ENTAIL: it has not shown the copy is unguarded. It
    // has not shown it is guarded either, so the judge is asked. Proving the flag-mediated case needs
    // path-sensitive reasoning this arbiter does not do.
    val boundedSink = boundedNames.exists(n => sink.name == n)
    val argNames    = sink.argument.ast.isIdentifier.name.l.distinct
    val bounds =
      if (!boundedSink || argNames.isEmpty) List.empty
      else
        sink.method.ast.isCall.code.l.filter(c =>
          boundShape.matcher(c).find() && argNames.exists(a => mentionsToken(c, List(a)))
        )

    // ONE ROW PER EVIDENCE KEY, not per path. Every field the driver reads is a property of the sink or of
    // (source kind, source, sanitized); only `length` varies per path, and the driver ranks by the shortest.
    // Emitting every path was a 100x payload term: ten real requests at callDepth 3 returned 3,838 rows
    // for 38 distinct keys, and a whole-repository scan would ship on the order of 130,000 rows to have
    // the reporter collapse them after they were paid for. `paths` keeps the count. Task 5.13.
    flows
      .map { flow =>
        val elements   = flow.elements.map(_.code).l
        val sanitized  = sanitizerNames.nonEmpty && flow.elements.l.exists(node => sanitizesHere(node))
        val sourceKind = sourceKindOf(flow.elements.l.headOption)
        ((sourceKind, elements.headOption.getOrElse("").take(200), sanitized), elements.size)
      }
      .groupBy(_._1)
      .toList
      .sortBy(_._1)
      .map { case ((sourceKind, source, sanitized), paths) =>
        ujson.Obj(
          "sink"            -> sink.code.take(200),
          "sourceKind"      -> sourceKind,
          "sinkLine"        -> sink.lineNumber.getOrElse(-1).toString,
          "sinkMethod"      -> sink.method.name,
          // Where the sink actually is. With callDepth > 0 that need not be the region's own file, and a
          // finding reported against the handler's file when the bug is in another module is unactionable.
          "sinkFile"        -> sink.method.filename,
          "source"          -> source,
          "sanitized"       -> sanitized,
          "length"          -> paths.map(_._2).min,
          "paths"           -> paths.size,
          "sinkArity"       -> arity,
          "sinkArg0Literal" -> arg0Literal,
          "bounded"         -> bounds.nonEmpty,
          "bound"            -> bounds.headOption.getOrElse("").take(120),
          "inLabeledScope"  -> (function.isEmpty || nestedInLabeled(sink.method) || reachableMethods.contains(sink.method.fullName))
        )
      }
  }

    rows
  }

  println("---OUSAST-CPG-BEGIN---")
  if (requestsJson.nonEmpty) {
    val parsed = ujson.read(requestsJson).obj
    val answers = parsed.map { case (id, req) =>
      def field(name: String): String = req.obj.get(name).map(_.str).getOrElse("")
      val paramSrc = req.obj.get("parameterSources").map(_.str).getOrElse("false")
      val fieldSrc = req.obj.get("fieldSources").map(_.str).getOrElse("true")
      val evidence = req.obj.get("evidenceOnly").map(_.str).getOrElse("false")
      id -> ujson.Arr(
        rowsFor(
          field("sources"),
          field("sinks"),
          field("sanitizers"),
          // Repository-wide, so the driver sends them ONCE as a top-level parameter rather than repeating
          // them in every request. The per-request form is still honoured for the tests and the single
          // -region path.
          if (field("hookCallbacks").nonEmpty) field("hookCallbacks") else hookCallbacks,
          if (field("dispatchApply").nonEmpty) field("dispatchApply") else dispatchApply,
          field("function"),
          paramSrc,
          fieldSrc,
          evidence,
          field("file"),
          field("callDepth"),
          field("boundedSinks")
        ): _*
      )
    }
    // A census of the graph, under a key no request id can collide with (ids are numbers). A frontend can
    // fail every file and STILL exit 0 with a valid, empty CPG -- `joern-parse` does not even propagate the
    // per-file warnings -- so "no rows" and "no graph" are indistinguishable to the driver without this.
    // It rides the batch rather than costing its own invocation, because JVM startup is what this whole
    // batching design exists to avoid.
    val census = ujson.Arr(ujson.Obj("methods" -> cpg.method.size.toString, "files" -> cpg.file.size.toString))
    println(ujson.write(ujson.Obj.from(answers.toSeq :+ ("__census__" -> census))))
  } else {
    println(
      ujson.write(ujson.Arr(rowsFor(sources, sinks, sanitizers, hookCallbacks, dispatchApply, function, parameterSources, fieldSources, evidenceOnly, file, callDepth, boundedSinks): _*))
    )
  }
  println("---OUSAST-CPG-END---")
}
