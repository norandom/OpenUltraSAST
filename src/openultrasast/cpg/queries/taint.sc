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
    dispatchValue: String = "",
    contextFilter: String = "",
    contextPaths: String = "",
    requests: String = "",
    requestsFile: String = "",
    trace: String = ""
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
  val fedFieldsMemo = scala.collection.mutable.Map.empty[String, Map[String, String]]
  val sourceMethodsMemo = scala.collection.mutable.Map.empty[String, Set[String]]
  val callbackFedMemo = scala.collection.mutable.Map.empty[String, String]
  // These four lived INSIDE `rowsFor` until 2026-09-11, which is to say they memoised nothing across the
  // requests of a batch: every pair re-walked the file's methods, re-collected its seeds, and re-ran the
  // field join's flow queries. Keyed by the parameters the answer depends on, so one family's seeds never
  // answer another's.
  val methodsByFile  = scala.collection.mutable.Map.empty[String, List[io.shiftleft.codepropertygraph.generated.nodes.Method]]
  val seedsByFile    = scala.collection.mutable.Map.empty[(String, String, String), List[io.shiftleft.codepropertygraph.generated.nodes.CfgNode]]
  val fieldTaintMemo = scala.collection.mutable.Map.empty[(String, String, String, String, String), Boolean]
  val hookKeysMemo   = scala.collection.mutable.Map.empty[(String, String, String), Set[String]]

  def rowsFor(
      sourcesS: String,
      sinksS: String,
      sanitizersS: String,
      hookCallbacksS: String,
      dispatchApplyS: String,
      dispatchValueS: String,
      functionS: String,
      paramSrc: String,
      fieldParamSrc: String,
      fieldSrc: String,
      evidenceS: String,
      fileS: String,
      depthS: String,
      boundedS: String,
      contextS: String = "",
      contextFilterS: String = "",
      contextPathsS: String = "",
      traceS: String = "",
      fixedOriginS: String = "",
      originAnchorsS: String = "",
      quotedSanitizersS: String = "",
      guardsS: String = ""
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

  // A full name is not source text: a `-` in it is part of an npm package's name, never an operator.
  // `require('mongodb-query-parser')` gives every call on the parser the full name `mongodb-query-parser...`,
  // and read as code that mentions the SQL sink `query` -- mongo-express's fixed pin was reported twice for
  // parsing a string with the very library its fix switched to.
  def fullNameMentions(fullName: String, token: String): Boolean = mentionsToken(fullName.replace('-', '_'), List(token))

  val sourcePatterns = split(sourcesS)
  val sinkNames      = split(sinksS)
  val sanitizerNames = split(sanitizersS)
  // Escapes (`esc_sql`) among the sanitizers, and the calls that build a string a value can land in; see
  // `cleansed`. Declared here because Scala forbids a forward reference across a value definition.
  val quotedOnly  = split(quotedSanitizersS).toSet
  val strictNames = sanitizerNames.filterNot(quotedOnly.contains)
  val quotedNames = sanitizerNames.filter(quotedOnly.contains)
  val stringBuilders = Set("<operator>.concat", "encaps", "<operator>.addition", "<operator>.formatString")
  val guardNames = split(guardsS).toSet
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
  // A call IS a source when the pattern names the call itself -- its callee or receiver, or the access it is
  // (`$_GET["c"]`, `req.body.x`) -- not when the pattern merely appears inside an argument. Matched on the
  // whole text, `apply_filters("h", md5("x"), $_GET["c"])` and `sanitize_text_field($_POST["x"])` were
  // sources themselves, so a filter's return was request data whatever it returned. The access inside the
  // argument is a source in its own right; nothing that reaches a sink through it is lost.
  // Of the operators, only an ACCESS names its own value: `$_GET["c"]`, `req.body.x`. A conditional or a
  // concatenation whose text contains `$_GET` is an expression built from the access, not the access -- matched
  // on its text, `isset($_GET["id"]) ? intval($_GET["id"]) : null` was itself a source, downstream of the cast.
  val accessOperators = Set(
    "<operator>.fieldAccess",
    "<operator>.indexAccess",
    "<operator>.indirectFieldAccess",
    "<operator>.indirectIndexAccess"
  )

  def isSourceCall(c: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean = {
    val named =
      if (accessOperators.contains(c.name)) c.code
      else if (c.name.startsWith("<operator")) ""
      else c.code.takeWhile(_ != '(')
    // Bounded, like every other token here: a substring test let Flask's `request.get` claim Django's
    // `request.get_host()` -- the host handed to the redirect VALIDATOR in wger's fix -- and both fixed
    // functions were reported as open redirects.
    named.nonEmpty && sourcePatterns.exists(p => mentionsToken(named, List(p)))
  }

  def frameworkSources = cpg.call.filter(isSourceCall)

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

  def methodsIn(fileName: String) =
    methodsByFile.getOrElseUpdate(fileName, cpg.method.filter(m => fileName.isEmpty || m.filename.endsWith(fileName)).l)

  // ---- which reported paths are PLAUSIBLE -------------------------------------------------------------
  //
  // Joern's dataflow is not field-sensitive on objects and treats a call's return as carrying its arguments.
  // Both are sound over-approximations, and on PHP classes they manufactured most of the false SQL injections
  // an adjudication found (PMPro, 2026-09-23: 2 of 10 sampled findings real). Traced element by element, every
  // false one took one of two steps no real injection needs:
  //
  //   A. THROUGH A QUERY. `$id = $wpdb->get_var("... '" . $token . "'")` is the injection, reported there. The
  //      engine then carried `$token` out through the query's RESULT -- `$id`, the row it loaded, the row's
  //      `user_id` -- into later queries. What a query returns is stored data, not request input.
  //   B. THROUGH THE OBJECT. Request data written to `$order->ProfileStartDate`, or passed as an argument to a
  //      method of `$wpdb`, taints the object as a whole; a DIFFERENT field read from it afterwards --
  //      `$this->membership_id`, `$wpdb->pmpro_memberships_users` -- came out tainted.
  //
  // So a path is dropped when it passes through a call to a sink of its own family, or when a field read is
  // reached through the bare object after the taint entered that object by writing another field or as an
  // argument of a method called ON it. Reading a member of an object that IS the tainted value -- the result
  // of `req.body`, of `JSON.parse(input)` -- is untouched, because there the object came out of a read or a
  // return, not into it.
  def familySinkCall(node: io.shiftleft.codepropertygraph.generated.nodes.AstNode): Boolean = node match {
    case c: io.shiftleft.codepropertygraph.generated.nodes.Call if !c.name.startsWith("<operator") =>
      val callee = c.code.takeWhile(_ != '(')
      sinkNames.exists(n => c.name == n || mentionsToken(callee, List(n)) || fullNameMentions(c.methodFullName, n))
    case _ => false
  }

  def objectHop(node: io.shiftleft.codepropertygraph.generated.nodes.AstNode): Boolean = node match {
    case _: io.shiftleft.codepropertygraph.generated.nodes.Identifier         => true
    case _: io.shiftleft.codepropertygraph.generated.nodes.MethodParameterIn  => true
    case _: io.shiftleft.codepropertygraph.generated.nodes.MethodParameterOut => true
    case _                                                                    => false
  }

  def fieldOf(c: io.shiftleft.codepropertygraph.generated.nodes.Call): String =
    c.argument.l.find(_.argumentIndex == 2).map(_.code.trim).getOrElse("")

  def assignedTo(id: io.shiftleft.codepropertygraph.generated.nodes.Identifier): Boolean =
    id.argumentIndex == 1 && (id.astParent match {
      case parent: io.shiftleft.codepropertygraph.generated.nodes.Call => parent.name == "<operator>.assignment"
      case _                                                           => false
    })

  def absorbedByObject(elements: List[io.shiftleft.codepropertygraph.generated.nodes.AstNode]): Boolean =
    elements.indices.exists { k =>
      elements(k) match {
        case read: io.shiftleft.codepropertygraph.generated.nodes.Call
            if k > 0 && read.name == "<operator>.fieldAccess" && objectHop(elements(k - 1)) =>
          var j = k - 1
          while (j >= 0 && objectHop(elements(j))) j -= 1
          if (j < 0) false // the object itself is where the path starts: it IS the tainted value
          else
            elements(j) match {
              // Through the SAME field -- written then read back, or read and read again -- is field-sensitive.
              case prior: io.shiftleft.codepropertygraph.generated.nodes.Call
                  if prior.name == "<operator>.fieldAccess" && fieldOf(prior) == fieldOf(read) =>
                false
              case _ =>
                // How did the value reach the object? Legitimately only by being ASSIGNED to it
                // (`$data = json_decode($input)`) or passed in as a parameter. An object merely used beside
                // the tainted value -- the receiver of a call that took it as an argument -- absorbed it.
                elements(j + 1) match {
                  case _: io.shiftleft.codepropertygraph.generated.nodes.MethodParameterIn => false
                  case id: io.shiftleft.codepropertygraph.generated.nodes.Identifier        => !assignedTo(id)
                  case _                                                                     => true
                }
            }
        case _ => false
      }
    }

  // The engine is field-INSENSITIVE on the object: a write to `$this->sql_order` taints `$this`, and the path
  // it reports can leave through the NEXT use of `$this` -- another field entirely -- and come back to
  // `$this->sql_order` later. Ultimate Member's CVE-2024-1071 is exactly that: the ORDER BY built in
  // `$this->sql_order` reaches the query, but the one path the engine gave went `$this` -> `$this->having` ->
  // `esc_sql($this->having)` -> ... -> `$this->sql_order`, which `absorbedByObject` rightly cut and which
  // credited an unrelated field's escape. Where a path leaves a field for ANOTHER field through the object and
  // later reads the first field again -- on the path, or inside the sink's argument the path ends at -- the
  // segment between is that detour, and it is spliced out. Only such a detour: an arbitrary loop may hold the
  // field's own re-sanitisation.
  def spliced(elements: List[io.shiftleft.codepropertygraph.generated.nodes.AstNode]): List[io.shiftleft.codepropertygraph.generated.nodes.AstNode] = {
    def isField(node: io.shiftleft.codepropertygraph.generated.nodes.AstNode) = node match {
      case c: io.shiftleft.codepropertygraph.generated.nodes.Call => c.name == "<operator>.fieldAccess"
      case _                                                      => false
    }
    val detour = elements.indices.iterator.flatMap { k =>
      elements(k) match {
        case read: io.shiftleft.codepropertygraph.generated.nodes.Call
            if k > 0 && read.name == "<operator>.fieldAccess" && objectHop(elements(k - 1)) =>
          var j = k - 1
          while (j >= 0 && objectHop(elements(j))) j -= 1
          if (j < 0 || !isField(elements(j))) None
          else {
            val left = elements(j).asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.Call]
            if (fieldOf(left) == fieldOf(read)) None
            else
              elements.indices.drop(k + 1).find(m => isField(elements(m)) && elements(m).code.trim == left.code.trim) match {
                case Some(m) => Some(elements.take(j) ++ elements.drop(m))
                case None =>
                  // The path may never read the field again and reach the sink's argument by sibling hops
                  // instead -- the query string that READS `$this->sql_order` is where it ends. A read of the
                  // same field inside that last element is the rejoin.
                  elements.lastOption.flatMap(last => last.ast.isCall.nameExact("<operator>.fieldAccess").find(_.code.trim == left.code.trim).map(r => (last, r))) match {
                    case Some((last, r)) if r.id != last.id => Some(elements.take(j) ++ List(r, last))
                    case _                                  => None
                  }
              }
          }
        case _ => None
      }
    }.nextOption()
    detour match {
      case Some(shorter) if shorter.size < elements.size => spliced(shorter)
      case _                                             => elements
    }
  }

  // Per element, not per path: the same nodes recur across thousands of paths of one sink, and walking each
  // path's calls afresh cost one outlier request 101 s -> 160 s.
  val familySinkMemo = scala.collection.mutable.Map.empty[Long, Boolean]

  // A registry read returns ONE of its arguments -- the dispatched value -- or nothing at all, per the facts'
  // `returns`/`value_arg`. A path that enters such a call through any other argument has used the engine's
  // default "every argument reaches the return", which is how `$this`, passed as filter context, turned a
  // random md5 fragment into an SQL injection.
  val dispatchValues: Map[String, Int] = split(dispatchValueS).flatMap { entry =>
    entry.split(":") match {
      case Array(name, position) => scala.util.Try(name.trim -> position.trim.toInt).toOption
      case _                     => None
    }
  }.toMap

  def offValueDispatch(elements: List[io.shiftleft.codepropertygraph.generated.nodes.AstNode]): Boolean =
    dispatchValues.nonEmpty && elements.indices.exists { k =>
      elements(k) match {
        case call: io.shiftleft.codepropertygraph.generated.nodes.Call if k > 0 && dispatchValues.contains(call.name) =>
          val position = dispatchValues(call.name)
          // The argument the path ENTERED by, which is the first of the run of this call's arguments right
          // before it: the engine hops between sibling arguments (`$_GET["c"]` -> `md5("x")` -> the call),
          // so the one immediately before the call can be the value argument when the data came in as context.
          val arguments = call.argument.l.map(a => a.id -> a).toMap
          var j = k - 1
          while (j >= 0 && arguments.contains(elements(j).id)) j -= 1
          if (j == k - 1) false
          else position == 0 || arguments(elements(j + 1).id).argumentIndex != position
        case _ => false
      }
    }

  // A destination is untrusted only where the value can choose WHERE it goes. OpenCVE redirects to
  // `reverse("cves") + "?" + request.GET.urlencode()` and to `reverse(route, kwargs={...})`: the request
  // decides the query string or a path segment, and the redirect stays on the site. So, for a sink fact that
  // says so, a path is cut when it enters a concatenation through anything but its LEFTMOST operand and that
  // operand already fixes the origin, or when it passes through an anchor call such as `reverse`. What does
  // NOT fix an origin is kept deliberately: `"/" + x` becomes `//evil.example`, and `"https://" + host` is the
  // attack itself.
  val originFixing = fixedOriginS == "true"
  val originAnchors = split(originAnchorsS).toSet
  val schemeHostThenPath = java.util.regex.Pattern.compile("^[A-Za-z][A-Za-z0-9+.-]*://[^/?#\\\\]+[/?#]")
  val concatenations = Set("<operator>.addition", "<operator>.assignmentPlus", "<operator>.formatString")
  val fixesOriginMemo = scala.collection.mutable.Map.empty[Long, Boolean]

  // A literal's TEXT: its code without the quotes, and without a Python string prefix.
  def literalText(code: String): String = {
    val quoted = "(?s)^(?:[rRbBuUfF]{1,2})?(['\"`])(.*)\\1$".r
    code.trim match {
      case quoted(_, inner) => inner
      case other            => other
    }
  }

  def literalFixesOrigin(code: String): Boolean = {
    // The literal's TEXT, without its quotes. With the closing quote left on, `"/"` read as `/"` and passed
    // the path test -- and `"/" + x` is the protocol-relative `//evil.example`.
    val text = literalText(code)
    text.startsWith("?") || text.startsWith("#") || text.matches("(?s)^/[^/\\\\].*") || schemeHostThenPath.matcher(text).find()
  }

  def fixesOrigin(node: io.shiftleft.codepropertygraph.generated.nodes.AstNode, depth: Int): Boolean =
    depth <= 3 && fixesOriginMemo.getOrElseUpdate(node.id, node match {
      case l: io.shiftleft.codepropertygraph.generated.nodes.Literal => literalFixesOrigin(l.code)
      case c: io.shiftleft.codepropertygraph.generated.nodes.Call if originAnchors.contains(c.name) => true
      case c: io.shiftleft.codepropertygraph.generated.nodes.Call if concatenations.contains(c.name) =>
        c.argument.l.sortBy(_.argumentIndex).headOption.exists(a => fixesOrigin(a, depth + 1))
      case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier =>
        // A variable fixes the origin when EVERY assignment to it in the method does.
        val writes = i.method.ast.isCall.nameExact(ASSIGNMENT).l.filter(_.argument.l.sortBy(_.argumentIndex).headOption.exists {
          case t: io.shiftleft.codepropertygraph.generated.nodes.Identifier => t.name == i.name
          case _                                                             => false
        })
        writes.nonEmpty && writes.forall(w => w.argument.l.find(_.argumentIndex == 2).exists(v => fixesOrigin(v, depth + 1)))
      case _ => false
    })

  // The argument of `call` that holds `node` -- the node itself or anywhere inside it. The engine does not
  // always step through the argument: `reverse("cves") + ("?" + request.GET.urlencode())` goes from
  // `request.GET` straight to the outer `+`.
  def argumentHolding(
      call: io.shiftleft.codepropertygraph.generated.nodes.Call,
      node: io.shiftleft.codepropertygraph.generated.nodes.AstNode
  ): Option[io.shiftleft.codepropertygraph.generated.nodes.Expression] =
    call.argument.l.find(a => a.id == node.id || a.ast.exists(_.id == node.id))

  def originFixed(elements: List[io.shiftleft.codepropertygraph.generated.nodes.AstNode]): Boolean =
    originFixing && elements.indices.exists { k =>
      elements(k) match {
        // Through an anchor: the value only fills the route's arguments. The anchor may be the path's last
        // element, which is the sink's own argument.
        case call: io.shiftleft.codepropertygraph.generated.nodes.Call if k > 0 && originAnchors.contains(call.name) => true
        // `url += "&" + q`: the engine goes from the right-hand side to the TARGET `url`, never visiting the
        // `+=` itself. The value is appended to what `url` already held.
        case target: io.shiftleft.codepropertygraph.generated.nodes.Identifier if k > 0 && target.argumentIndex == 1 =>
          target.astParent match {
            case augmented: io.shiftleft.codepropertygraph.generated.nodes.Call if augmented.name == "<operator>.assignmentPlus" =>
              argumentHolding(augmented, elements(k - 1)).exists(_.argumentIndex == 2) && fixesOrigin(target, 0)
            case _ => false
          }
        case call: io.shiftleft.codepropertygraph.generated.nodes.Call if k > 0 && concatenations.contains(call.name) =>
          // The argument the path entered by, as in `offValueDispatch`: the first of the run of elements
          // right before the call that lie inside its arguments.
          var j = k - 1
          while (j >= 0 && argumentHolding(call, elements(j)).isDefined) j -= 1
          j < k - 1 && argumentHolding(call, elements(j + 1)).exists { entered =>
            val leftmost = call.argument.l.sortBy(_.argumentIndex).headOption
            entered.argumentIndex > 1 && leftmost.exists(l => l.argumentIndex < entered.argumentIndex && fixesOrigin(l, 0))
          }
        case _ => false
      }
    }

  def plausible(flow: io.joern.dataflowengineoss.language.Path): Boolean = {
    val elements = spliced(flow.elements.l)
    val throughSink = elements.dropRight(1).exists {
      case c: io.shiftleft.codepropertygraph.generated.nodes.Call if !c.name.startsWith("<operator") =>
        familySinkMemo.getOrElseUpdate(c.id, familySinkCall(c))
      case _ => false
    }
    !throughSink && !offValueDispatch(elements) && !originFixed(elements) && !(elements.exists {
      case c: io.shiftleft.codepropertygraph.generated.nodes.Call => c.name == "<operator>.fieldAccess"
      case _                                                      => false
    } && absorbedByObject(elements))
  }

  // Framework sources are untrusted wherever they appear. Parameters are untrusted only where the caller has
  // said this region is an entry point -- the same contract `parameterNodes` carries, and for the same
  // reason: an arbitrary helper's parameters carry whatever its caller happened to have.
  def seedsIn(fileName: String) =
    seedsByFile.getOrElseUpdate(
      (sourcesS, fieldParamSrc, fileName), {
        val methods = methodsIn(fileName)
        val framework: List[io.shiftleft.codepropertygraph.generated.nodes.CfgNode] =
          methods.flatMap(_.ast.isCall.filter(isSourceCall).l)
        val params: List[io.shiftleft.codepropertygraph.generated.nodes.CfgNode] =
          if (fieldParamSrc == "true") methods.flatMap(_.parameter.l) else Nil
        framework ++ params
      }
    )

  // The join carries OBJECT STATE between methods: `$this->attachments` written in the constructor, read in
  // `_delete_files()`. That is what a field keyed by its text means only when the base IS the object. Any other
  // base is a variable, and the same text in two functions names two variables: PMPro's
  // `$user = new stdClass; $user->ID = $_POST['user_id']` in one function made the `WP_User` parameter's
  // `$user->ID` in another an SQL injection source. So a non-object base is joined within its own method only,
  // where it is one variable -- and where the engine's own dataflow already sees it.
  val objectBases = Set("$this", "this", "self")

  def fieldScope(fieldCode: String, reader: io.shiftleft.codepropertygraph.generated.nodes.Method): String = {
    val base = fieldCode.split("->|\\.").headOption.map(_.trim).getOrElse("")
    if (objectBases.contains(base)) "" else reader.fullName
  }

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
  def sanitizesHere(node: io.shiftleft.codepropertygraph.generated.nodes.AstNode, names: List[String] = sanitizerNames): Boolean = {
    val code = node.code
    val byName = node match {
      case call: io.shiftleft.codepropertygraph.generated.nodes.Call => names.exists(n => call.name == n)
      case _                                                        => false
    }
    byName || names.exists(n => code.startsWith(n + "(") || code.contains("'" + n + "'") || code.contains("\"" + n + "\""))
  }

  // A sanitizer the value passes THROUGH between two path elements. The engine can step from a sanitizer's
  // argument straight to the expression around the call -- `$params["id"]` inside
  // `isset($params["id"]) ? intval($params["id"]) : null` went to the conditional, and `intval` itself was
  // never an element -- so checking elements alone reported PMPro's integer-cast REST level id as an SQL
  // injection. Where the next element CONTAINS the previous one, the syntax between them is what the value
  // was wrapped in; a sanitizer there sanitized it. A sanitizer elsewhere in the expression does not count.
  def sanitizedBetween(elements: List[io.shiftleft.codepropertygraph.generated.nodes.AstNode], names: List[String] = sanitizerNames): Boolean =
    elements.zip(elements.drop(1)).exists { case (inner, outer) => wrappedBetween(inner, outer, names) }

  def wrappedBetween(
      inner: io.shiftleft.codepropertygraph.generated.nodes.AstNode,
      outer: io.shiftleft.codepropertygraph.generated.nodes.AstNode,
      names: List[String]
  ): Boolean = {
      var node: Option[io.shiftleft.codepropertygraph.generated.nodes.AstNode] = inner._astIn.nextOption() match {
        case Some(parent: io.shiftleft.codepropertygraph.generated.nodes.AstNode) => Some(parent)
        case _                                                                     => None
      }
      var wrapped = false
      var reached = false
      var depth   = 0
      while (node.isDefined && !reached && depth < 8) {
        val current = node.get
        if (current.id == outer.id) reached = true
        else {
          if (sanitizesHere(current, names)) wrapped = true
          node = current._astIn.nextOption() match {
            case Some(parent: io.shiftleft.codepropertygraph.generated.nodes.AstNode) => Some(parent)
            case _                                                                     => None
          }
          depth += 1
        }
      }
      reached && wrapped
  }

  // An ESCAPE protects a value only inside a quoted literal. The credit is withdrawn where the first string the
  // escaped value is built into leaves it OUTSIDE quotes: the literal text before it opens no quote.
  // Ultimate Member's `$sortby = esc_sql(...); " ORDER BY u.{$sortby} "` read as sanitized, and is
  // CVE-2024-1071. With no string built downstream the credit stays, as it always has.

  // The literal text of `root` that precedes `holder`, walking nested string builders in argument order.
  def textBefore(
      root: io.shiftleft.codepropertygraph.generated.nodes.Call,
      holder: io.shiftleft.codepropertygraph.generated.nodes.AstNode
  ): String = {
    val text = new StringBuilder
    def walk(node: io.shiftleft.codepropertygraph.generated.nodes.AstNode): Boolean =
      if (node.id == holder.id) true
      else
        node match {
          case l: io.shiftleft.codepropertygraph.generated.nodes.Literal => text.append(literalText(l.code)); false
          case c: io.shiftleft.codepropertygraph.generated.nodes.Call if stringBuilders.contains(c.name) =>
            c.argument.l.sortBy(_.argumentIndex).exists(walk)
          case _ => false
        }
    walk(root)
    text.toString
  }

  def opensQuote(text: String): Boolean = {
    val singles = text.count(_ == '\'')
    val doubles = "\\\"".r.findAllMatchIn(text).size
    singles % 2 == 1 || doubles % 2 == 1
  }

  def landsQuoted(elements: List[io.shiftleft.codepropertygraph.generated.nodes.AstNode], from: Int): Boolean =
    elements.indices.drop(from).find { m =>
      elements(m) match {
        case c: io.shiftleft.codepropertygraph.generated.nodes.Call => m > 0 && stringBuilders.contains(c.name)
        case _                                                      => false
      }
    } match {
      case None => true
      case Some(m) =>
        val builder = elements(m).asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.Call]
        argumentHolding(builder, elements(m - 1)) match {
          case None         => true
          case Some(holder) => opensQuote(textBefore(builder, holder))
        }
    }

  // A GUARD is a check, not a transformation, so it is judged by WHERE the flow is relative to it:
  //   * inside the branch its condition selects -- `if next_url and url_has_allowed_host_and_scheme(next_url)`
  //     around the redirect, `elseif (in_array($sortby, $allowed, true)) { ... }` around the query;
  //   * past it, when its failure exits or overwrites the value -- `if not ...(next_url): next_url = reverse(..)`
  //     -- and the check dominates the end of the flow;
  //   * through the arm of a ternary it selects -- `in_array(strtoupper($o), ['ASC','DESC'], true) ? $o : 'ASC'`.
  // The guard must test a variable the path itself carries. Polarity is read off the condition: a positive
  // guard sits under nothing but `&&`; a failure test is exactly one `!` under nothing but `||`.
  val exitCalls = Set("exit", "die", "wp_die", "abort", "<operator>.throw")

  def carried(elements: List[io.shiftleft.codepropertygraph.generated.nodes.AstNode]): Set[String] =
    elements.flatMap {
      case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => List(i.name, i.code.trim)
      case c: io.shiftleft.codepropertygraph.generated.nodes.Call if c.name == FIELD_ACCESS => List(c.code.trim)
      case _ => Nil
    }.toSet

  def guardsIn(root: io.shiftleft.codepropertygraph.generated.nodes.AstNode, names: Set[String]): List[io.shiftleft.codepropertygraph.generated.nodes.Call] =
    if (guardNames.isEmpty) Nil
    else
      // Only the TESTED value is validated -- the first argument: `in_array`'s needle, the URL a redirect check is
      // given. PMPro's `in_array( 'E', $levels )` asks whether a constant is in `$levels`; with any argument
      // counted, it discharged a flow through `$levels` itself.
      root.ast.isCall.l.filter(g => guardNames.contains(g.name)).filter { g =>
        g.argument.l.filter(_.argumentIndex == 1).exists(_.ast.exists {
          case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier                       => names(i.name) || names(i.code.trim)
          case c: io.shiftleft.codepropertygraph.generated.nodes.Call if c.name == FIELD_ACCESS => names(c.code.trim)
          case _                                                                                 => false
        })
      }

  // Some(true): the guard holds wherever the condition does. Some(false): the condition says it FAILED.
  def polarity(g: io.shiftleft.codepropertygraph.generated.nodes.AstNode, root: io.shiftleft.codepropertygraph.generated.nodes.AstNode): Option[Boolean] = {
    var node = g
    var nots, ands, ors = 0
    var other = false
    while (node.id != root.id && !other) {
      node._astIn.nextOption() match {
        case Some(parent: io.shiftleft.codepropertygraph.generated.nodes.Call) =>
          parent.name match {
            case "<operator>.logicalNot" => nots += 1
            case "<operator>.logicalAnd" => ands += 1
            case "<operator>.logicalOr"  => ors += 1
            case _                       => other = true
          }
          node = parent
        case Some(parent: io.shiftleft.codepropertygraph.generated.nodes.AstNode) if parent.id == root.id => node = parent
        case _ => other = true
      }
    }
    if (other) None
    else if (nots == 0 && ors == 0) Some(true)
    else if (nots == 1 && ands == 0) Some(false)
    else None
  }

  def branches(cs: io.shiftleft.codepropertygraph.generated.nodes.ControlStructure) = {
    val children = cs.astChildren.l.sortBy(_.order)
    (children.find(_.order == 2), children.find(_.order == 3))
  }

  def contains(root: io.shiftleft.codepropertygraph.generated.nodes.AstNode, node: io.shiftleft.codepropertygraph.generated.nodes.AstNode) =
    root.id == node.id || root.ast.exists(_.id == node.id)

  def guarded(elements: List[io.shiftleft.codepropertygraph.generated.nodes.AstNode]): Boolean =
    guardNames.nonEmpty && elements.nonEmpty && {
      val names = carried(elements)
      val end = elements.last
      val ternary = elements.indices.exists { k =>
        elements(k) match {
          // The engine may enter through the CONDITION's own copy of the value (`in_array(strtoupper($o), ..)`),
          // which never becomes the result. What the ternary can return is its arms; with the check holding on
          // the carried value and the other arm unable to carry it, the result is the checked value or a constant.
          case c: io.shiftleft.codepropertygraph.generated.nodes.Call if k > 0 && c.name == "<operator>.conditional" =>
            val args = c.argument.l
            def carries(arm: io.shiftleft.codepropertygraph.generated.nodes.AstNode) = arm.ast.exists {
              case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier                       => names(i.name) || names(i.code.trim)
              case f: io.shiftleft.codepropertygraph.generated.nodes.Call if f.name == FIELD_ACCESS => names(f.code.trim)
              case _                                                                                 => false
            }
            argumentHolding(c, elements(k - 1)).exists(a => a.argumentIndex == 1 || a.argumentIndex == 2) &&
              args.find(_.argumentIndex == 1).exists(cond => guardsIn(cond, names).exists(g => polarity(g, cond).contains(true))) &&
              !args.find(_.argumentIndex == 3).exists(carries)
          case _ => false
        }
      }
      // Where the check is judged: the end of the flow, and every point where the path STORES the value. A
      // store made while the check held carries it forward -- Ultimate Member writes `$this->sql_order` inside
      // `elseif (in_array($sortby, ...))` and passes it through a filter after the chain. A mere READ inside a
      // branch is not a candidate: the engine lists uses in branches the flow does not depend on.
      def stored(node: io.shiftleft.codepropertygraph.generated.nodes.AstNode) = node match {
        case e: io.shiftleft.codepropertygraph.generated.nodes.Expression if e.argumentIndex == 1 =>
          e.astParent match {
            case a: io.shiftleft.codepropertygraph.generated.nodes.Call => a.name.startsWith("<operator>.assignment")
            case _                                                      => false
          }
        case _ => false
      }
      ternary || (end :: elements.filter(stored)).distinctBy(_.id).exists {
        case cfg: io.shiftleft.codepropertygraph.generated.nodes.CfgNode =>
          val method = cfg.method
          method.ast.isControlStructure.controlStructureType("IF").l.exists { cs =>
            cs.condition.l.headOption.exists { cond =>
              val checks = guardsIn(cond, names)
              checks.nonEmpty && {
                val (whenTrue, _) = branches(cs)
                val inside = whenTrue.exists(b => contains(b, cfg)) && checks.exists(g => polarity(g, cond).contains(true))
                inside || (checks.exists(g => polarity(g, cond).contains(false)) && whenTrue.exists { b =>
                  val bails = b.ast.exists {
                    case _: io.shiftleft.codepropertygraph.generated.nodes.Return => true
                    case c: io.shiftleft.codepropertygraph.generated.nodes.Call    => exitCalls.contains(c.name)
                    case _                                                          => false
                  }
                  val overwrites = b.ast.isCall.nameExact(ASSIGNMENT).l.exists(_.argument.l.find(_.argumentIndex == 1).exists {
                    case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => names(i.name) || names(i.code.trim)
                    case _                                                             => false
                  })
                  (bails || overwrites) && !contains(cs, cfg) && (cond match {
                    case c: io.shiftleft.codepropertygraph.generated.nodes.CfgNode => cfg.dominatedBy.exists(_.id == c.id)
                    case _                                                          => false
                  })
                })
              }
            }
          }
        case _ => false
      }
    }

  def cleansed(elements: List[io.shiftleft.codepropertygraph.generated.nodes.AstNode]): Boolean =
    guarded(elements) || elements.exists(node => sanitizesHere(node, strictNames)) || sanitizedBetween(elements, strictNames) ||
      (quotedNames.nonEmpty && elements.indices.exists { k =>
        (sanitizesHere(elements(k), quotedNames) ||
          (k + 1 < elements.size && wrappedBetween(elements(k), elements(k + 1), quotedNames))) && landsQuoted(elements, k + 1)
      })

  def fieldIsTainted(fileName: String, fieldCode: String, scope: String = ""): Boolean =
    fieldTaintMemo.getOrElseUpdate(
      (sourcesS, fieldParamSrc, sanitizersS + "|" + quotedSanitizersS, fileName, scope + "|" + fieldCode), {
        val seeds = seedsIn(fileName)
        if (seeds.isEmpty) false
        else
          methodsIn(fileName)
            .filter(m => scope.isEmpty || m.fullName == scope)
            .flatMap(_.ast.isCall.nameExact(ASSIGNMENT).l)
            .exists { assignment =>
            val args = assignment.argument.l
            args.size >= 2 && (args.head match {
              case target: io.shiftleft.codepropertygraph.generated.nodes.Call
                  if target.name == FIELD_ACCESS && target.code.trim == fieldCode =>
                // The summary must carry the SANITIZATION status of the half it summarises, not merely its
                // reachability. Asking only "does a source reach this assignment" marks
                // `$this->sqlQuery = "..." . esc_sql($x) . "..."` tainted, and PMPro builds most of its
                // queries that way: the fixed side of its pair went from 1 finding to 13 without this,
                // which is the pair no longer separating at all.
                val flows = args(1).start.reachableByFlows(seeds.iterator).l.filter(plausible)
                //
                // Judged exactly as a flow's row is: an ESCAPE counts only where the value lands quoted. Ultimate
                // Member builds `$this->sql_order = " ORDER BY u.{$sortby} "` from an `esc_sql`'d value, and a
                // test for any sanitizer NAME on the path marked the field clean -- the one deterministic route
                // to CVE-2024-1071, while the engine's own path to the query was a coin toss between runs.
                flows.exists(f => !cleansed(spliced(f.elements.l)))
              case _ => false
            })
          }
      }
    )

  // A read of a MEMBER of a tainted object is tainted too. WP Statistics assigns the whole request to
  // `$this->rest_hits` in one method and reads `$this->rest_hits->current_page_id` in another, so an exact
  // code match sees two unrelated strings where the source text says one is inside the other. Every prefix
  // that ends on a `->` boundary is checked, left to right.
  def taintedPrefixes(code: String, fileName: String, reader: io.shiftleft.codepropertygraph.generated.nodes.Method): Boolean = {
    val parts = code.split("->").map(_.trim).filter(_.nonEmpty)
    if (parts.length < 2) false
    else
      (2 to parts.length).exists { n =>
        val prefix = parts.take(n).mkString("->")
        fieldIsTainted(fileName, prefix, fieldScope(prefix, reader))
      }
  }

  // Off by request only, and defaulting to ON when the field is absent, so nothing about the shipped
  // behaviour depends on a caller remembering to set it. It exists so the join can be measured against
  // itself: a cost you cannot switch off is a cost you cannot attribute.
  // A field read is a source only where it reads OBJECT STATE -- a value some other method left there. Two
  // reads are not that:
  //   * the target of a write (`$this->sqlQuery = ...`), which is a field-access node like any read;
  //   * a read the method's own write to the same field dominates. Every PMPro `MemberOrder` method builds its
  //     statement in `$this->sqlQuery` and runs it at once; because one method writes request data there, the
  //     join marked the field tainted everywhere, and `deleteMe()` -- which had just set it from the internal
  //     `$this->id` -- became an SQL injection. After a dominating write the value is the method's own, and if
  //     that write carries request data the ordinary flow from the source already finds it.
  def writeTarget(c: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean =
    c.argumentIndex == 1 && (c.astParent match {
      case parent: io.shiftleft.codepropertygraph.generated.nodes.Call => parent.name == ASSIGNMENT
      case _                                                           => false
    })

  def overwrittenBefore(read: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean =
    read.dominatedBy.isCall
      .nameExact(ASSIGNMENT)
      .exists(a => a.argument.l.find(_.argumentIndex == 1).exists(_.code.trim == read.code.trim))

  def fieldSourceNodes =
    if (fieldSrc != "true") Iterator.empty
    else {
      val reads = cpg.call.nameExact(FIELD_ACCESS).filter(c => inScope(c.method)).l.filterNot(writeTarget)
      if (reads.isEmpty) Iterator.empty
      else reads.filter(r => taintedPrefixes(r.code.trim, fileS, r.method) && !overwrittenBefore(r)).iterator
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
      callback.ast.isCall.filter(isSourceCall).l
    val fields: List[io.shiftleft.codepropertygraph.generated.nodes.CfgNode] =
      callback.ast.isCall.nameExact(FIELD_ACCESS).l.filter(r => taintedPrefixes(r.code.trim, callback.filename, r.method))
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

  def keyOf(access: io.shiftleft.codepropertygraph.generated.nodes.Call): String =
    access.argument.l.lift(1).map(a => unquote(a.code)).getOrElse("")

  def taintedKeysOf(callback: String): Set[String] =
    hookKeysMemo.getOrElseUpdate(
      (sourcesS, sanitizersS, callback),
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
                      else if (args(1).start.reachableByFlows(seeds.iterator).l.filter(plausible).exists(f => !cleansed(spliced(f.elements.l))))
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
  // Fourth instance of the same bug class, and this one word-bounding did not catch. NodeGoat's signup handler
  // is one `<operator>.assignment` node whose code is the entire 1,000-character arrow function, and inside it
  // a comment reads `// set these up in case we have an error case`. `set` is a prototype-pollution sink, the
  // word is bounded, and the match was reported as a prototype finding on a handler that calls no `set` at
  // all. Searching a node's whole text asks "is this word anywhere near here", which is not the question.
  //
  // So the text clause is confined to the CALLEE -- everything before the first argument -- which is the only
  // part of a call that names what is being called, and operators are excluded from it entirely: an
  // assignment is not a call to a library function, whatever its right-hand side happens to spell.
  def calleeText(code: String): String = {
    val open = code.indexOf('(')
    if (open < 0) code else code.substring(0, open)
  }

  def sinkMatches(c: io.shiftleft.codepropertygraph.generated.nodes.Call, n: String): Boolean = {
    val operator = c.name.startsWith("<operator")
    c.name == n || (!operator && (mentionsToken(calleeText(c.code), List(n)) || fullNameMentions(c.methodFullName, n)))
  }

  // The candidate sink calls for a FAMILY do not depend on the region, and scanning every call in the graph
  // for each of 2,487 requests was a large share of what made a request cost seconds -- in evidence mode,
  // which asks for no dataflow at all, it alone took a query past an hour. Scanned once per sink list and
  // kept for the batch; the per-request work is the scope filter over that list.
  def sinkCalls =
    sinkCandidatesMemo
      .getOrElseUpdate(sinksS, cpg.call.filter(c => sinkNames.exists(n => sinkMatches(c, n))).l)
      .filter(c => inScope(c.method))

  // ---- stage one of the two-stage join WITHOUT dataflow, for evidence mode (flow-aware-ranking, phase 2) --
  //
  // The arbiter's `carried` runs a `reachableByFlows` per candidate assignment, and over a whole
  // repository's evidence pass that was not a cost but a wall: pmpro's 22,315 pairs went from 255 s to
  // past 1,800 s and answered nothing. Evidence is allowed to be a structural proxy -- the brief says so
  // of every path field -- so this asks the cheap form of the same two questions: is a field the region
  // reads ASSIGNED, anywhere in its file, from a source expression or from a parameter of the assigning
  // method (`$this->attachments = $attachments` in a constructor is the MW WP Form case); and does a hook
  // applied in scope have a registered callback whose body holds a source or such a field read (WP
  // Statistics's `set_current_page`). Memoised per file and per callback for the batch. It orders; the
  // arbiter still decides with the flow.
  // Provenance matters: "source" (assigned from a source expression, or from a same-file method that
  // reads one) is the strong form and promotes a tier; "parameter" (assigned from a parameter of the
  // assigning method -- every constructor does this) is weak and only orders within one. Measured: with
  // the two folded together tier 4 held 555 of pmpro's regions and 569 of WP Statistics's.
  def strongest(kinds: Iterable[String]): String =
    if (kinds.exists(_ == "source")) "source" else if (kinds.exists(_ == "parameter")) "parameter" else ""

  def prefixKind(code: String, fed: Map[String, String]): String = {
    val parts = code.split("->").map(_.trim).filter(_.nonEmpty)
    if (parts.length < 2) "" else strongest((2 to parts.length).flatMap(n => fed.get(parts.take(n).mkString("->"))))
  }

  // Methods of a file whose body reads a source: one level of "assigned from a call". WP Statistics writes
  // `$this->rest_hits = (object) self::rest_params()` and `rest_params()` is where `$_REQUEST` is read.
  def sourceMethods(fileName: String): Set[String] =
    sourceMethodsMemo.getOrElseUpdate(
      fileName,
      methodsIn(fileName).filter(m => m.ast.isCall.exists(c => mentionsToken(c.code, sourcePatterns))).map(_.name).toSet
    )

  def fedFields(fileName: String): Map[String, String] =
    fedFieldsMemo.getOrElseUpdate(
      fileName, {
        val readers = sourceMethods(fileName)
        methodsIn(fileName).flatMap { m =>
          val params = m.parameter.name.l.filterNot(_ == "this").toSet
          m.ast.isCall.nameExact(ASSIGNMENT).l.flatMap { assignment =>
            val args = assignment.argument.l
            if (args.size < 2) None
            else
              args.head match {
                case target: io.shiftleft.codepropertygraph.generated.nodes.Call if target.name == FIELD_ACCESS =>
                  val rhs = args(1)
                  val fromParameter = rhs match {
                    case id: io.shiftleft.codepropertygraph.generated.nodes.Identifier => params.contains(id.name)
                    case _                                                             => false
                  }
                  val fromSource = mentionsToken(rhs.code, sourcePatterns) || (readers.nonEmpty && rhs.ast.isCall.name.l.exists(readers.contains))
                  if (fromSource) Some(target.code.trim -> "source")
                  else if (fromParameter) Some(target.code.trim -> "parameter")
                  else None
                case _ => None
              }
          }
        }.groupBy(_._1).map { case (field, kinds) => field -> strongest(kinds.map(_._2)) }
      }
    )

  def fieldCarriedKind: String =
    strongest(cpg.call.nameExact(FIELD_ACCESS).filter(c => inScope(c.method)).l.map(r => prefixKind(r.code.trim, fedFields(r.method.filename))))

  def callbackFedKind(callback: String): String =
    callbackFedMemo.getOrElseUpdate(
      callback,
      strongest(cpg.method.nameExact(callback).l.map { m =>
        if (m.ast.isCall.exists(c => mentionsToken(c.code, sourcePatterns))) "source"
        else {
          val fed = fedFields(m.filename)
          if (fed.isEmpty) "" else strongest(m.ast.isCall.nameExact(FIELD_ACCESS).code.l.map(code => prefixKind(code.trim, fed)))
        }
      })
    )

  def hookCarriedKind: String =
    if (hookTable.isEmpty || hookApply.isEmpty) ""
    else
      strongest(cpg.call.filter(c => hookApply.contains(c.name)).filter(c => inScope(c.method)).l.flatMap { call =>
        val hook = call.argument.l.headOption.map(a => unquote(a.code)).getOrElse("")
        hookTable.getOrElse(hook, Nil).map(callbackFedKind)
      })

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
      methodSourceMemo.getOrElseUpdate(m.fullName, m.ast.isCall.exists(c => mentionsToken(c.code, sourcePatterns)))
    val sinkList    = sinkCalls.l
    val sourceLocal = labeledMethods.exists(methodHasSource)
    val sourceNear  = depth > 0 && cpg.method.fullNameExact(reachableMethods.toSeq: _*).exists(methodHasSource)
    // Anywhere in the repository at all. Exact at every callDepth, and the cheapest cut there is: a family
    // with no sink anywhere cannot produce a flow for any region. Memoised on the sink list, because it is
    // the same answer for every request of one family and a repository-wide walk per request turned a
    // milliseconds-per-pair query into minutes.
    val familyInRepo = familyInRepoMemo.getOrElseUpdate(sinksS, cpg.call.exists(c => sinkNames.exists(n => sinkMatches(c, n))))
    // `carried`: stage one of the two-stage join as STRUCTURE, not flow -- see `fedFields` above for why the
    // flow form was a wall. It puts `_delete_files()` (fed by `$this->attachments`) and `record()` (fed by
    // a filter) where their sources say, instead of one tier below every region with a `$_GET` in its own
    // body. Asked only where there is a sink to carry to, so a plugin's 21,000 tier-0 pairs pay nothing.
    // Weak becomes strong only when the FLOW says so. A parameter-fed field is what every constructor
    // makes and what MW WP Form's `_delete_files()` is actually fed by; structure cannot tell the two
    // apart, the join can. So the exact form is asked here for exactly the parameter-fed fields a
    // sink-bearing region reads -- memoised per (family, file, field) for the batch -- and nowhere else.
    // That bounds the flow queries to the cases the structure could not settle, instead of the 1,040
    // sink-bearing pairs that did not finish in 1,800 s.
    val structuralKind = if (sinkList.nonEmpty && familyInRepo) strongest(List(fieldCarriedKind, hookCarriedKind)) else ""
    val carriedKind =
      if (structuralKind != "parameter") structuralKind
      else {
        val confirmed = cpg.call
          .nameExact(FIELD_ACCESS)
          .filter(c => inScope(c.method))
          .l
          .exists(r => prefixKind(r.code.trim, fedFields(r.method.filename)) == "parameter" && taintedPrefixes(r.code.trim, r.method.filename, r.method))
        if (confirmed) "source" else "parameter"
      }
    val carried = carriedKind.nonEmpty
    val summary = ujson.Obj(
      "kind"         -> "summary",
      "sinks"        -> sinkList.size,
      "sourceLocal"  -> sourceLocal,
      "sourceNear"   -> sourceNear,
      "carried"      -> carried,
      "carriedKind"  -> carriedKind,
      "carriedBy"    -> (if (structuralKind.isEmpty) "" else if (fieldCarriedKind == structuralKind) "field" else "hook"),
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
    // Export locations already used by this query, for change attribution only. No new
    // source/sink/guard inference and no change to the evidence vector or its weights.
    val contextRows = if (contextS != "true") Nil else {
      def location(m: io.shiftleft.codepropertygraph.generated.nodes.Method, kind: String): ujson.Obj =
        ujson.Obj("kind" -> "context_method", "path" -> m.filename, "function" -> m.name,
          "startLine" -> m.lineNumber.getOrElse(-1), "endLine" -> m.lineNumberEnd.getOrElse(-1),
          "relationship" -> kind)
      val scoped = cpg.method.filterNot(_.isExternal).filter(m => inScope(m)).l
      // Field carrying is deliberately same-file in the existing abstraction. Retain
      // its file context conservatively, never claim every method carries the value.
      val fieldFiles = if (fieldCarriedKind.isEmpty) Set.empty[String] else
        cpg.call.nameExact(FIELD_ACCESS).filter(c => inScope(c.method)).l.map(_.method.filename).toSet
      val callbacks = if (hookApply.isEmpty) Nil else cpg.call.filter(c => hookApply.contains(c.name))
        .filter(c => inScope(c.method)).l.flatMap { call =>
          val hook = call.argument.l.headOption.map(a => unquote(a.code)).getOrElse("")
          hookTable.getOrElse(hook, Nil).flatMap(name => cpg.method.nameExact(name).filterNot(_.isExternal).l)
        }.distinct
      // Export sanitizer locations as guard context, not proof of discharge. Removed
      // guards are retained through base spans and unchanged-line correspondence.
      val located: List[(io.shiftleft.codepropertygraph.generated.nodes.Method, String)] =
        scoped.map(m => m -> (if (labeledMethods.exists(_.id == m.id)) "entry" else "callee")) ++
          fieldFiles.toList.flatMap(f => methodsIn(f).filterNot(_.isExternal).map(_ -> "field")) ++
          callbacks.map(_ -> "hook") ++
          scoped.filter(_.ast.l.exists(node => sanitizesHere(node))).map(_ -> "guard")
      // ONLY THE CHANGED FILES are itemised when the driver says which they are. The consumer attaches a
      // location to a change only when the location's file is one the change touched, and discards every
      // other row after checking it names a real file with a sane extent. Itemised anyway, a request whose
      // scope reaches a vendored SDK returned 1,845 rows, 200 of them 9.4 MB, and the whole-repository pass
      // on a WordPress plugin never finished a push. Everything else collapses into ONE row carrying exactly
      // what that check reads: the distinct files and how many locations had no usable extent.
      val itemise = contextFilterS != "true"
      // Newline-separated: a path may hold a comma, and the driver never filters when one holds a newline.
      val changedFiles = contextPathsS.split("\n").map(_.trim).filter(_.nonEmpty).toList
      def touched(m: io.shiftleft.codepropertygraph.generated.nodes.Method): Boolean =
        itemise || changedFiles.exists(p => m.filename == p || m.filename.endsWith("/" + p))
      val (kept, elsewhere) = located.partition { case (m, _) => touched(m) }
      val locations = kept.map { case (m, relationship) => location(m, relationship) }
      val elsewhereRows =
        if (elsewhere.isEmpty) Nil
        else {
          val unusable = elsewhere.count { case (m, _) =>
            val start = m.lineNumber.getOrElse(-1)
            start < 1 || m.lineNumberEnd.getOrElse(-1) < start
          }
          List(ujson.Obj("kind" -> "context_elsewhere", "locations" -> elsewhere.size, "unusableExtents" -> unusable,
            "paths" -> ujson.Arr.from(elsewhere.map(_._1.filename).distinct.sorted)))
        }
      // Reachability remains bounded. External/dynamic calls and calls outside the
      // current reachability set cannot establish a complete negative for a change.
      // A modeled argument does not summarize its consumer: unknown(req.body),
      // unknown(eval(...)) and unknown("escape") all retain an external boundary.
      // Only the directly invoked fact-named operation can use this exemption.
      def directlyModeled(c: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean =
        (sinkNames ++ sanitizerNames ++ sourcePatterns).exists { raw =>
          val name = raw.stripSuffix("(")
          c.name == name || c.code.startsWith(name + "(")
        }
      val missing = scoped.exists(m => m.ast.isCall.l.exists { c =>
        !c.name.startsWith("<operator>") && !directlyModeled(c) && {
          val destinations = c.callee.l
          destinations.isEmpty || destinations.exists(d => d.isExternal || !inScope(d))
        }
      })
      // An empty scope has two different causes and they are not interchangeable. A file the
      // frontend produced no methods for is one thing; a question naming a function this file does
      // not define is another, and it is the common one: a route-registration module names handlers
      // that live in other files, so the graph rightly holds no such method here. Reporting both as
      // "scope empty" hides which is which, and only the second names something a reader can act on.
      val boundaries =
        if (function.nonEmpty && scoped.isEmpty)
          List(ujson.Obj("kind" -> "context_boundary", "reason" -> "context_function_unresolved:contributor-scan", "function" -> function))
        else if (scoped.isEmpty)
          List(ujson.Obj("kind" -> "context_boundary", "reason" -> "context_scope_empty:contributor-scan"))
        else if (missing)
          List(ujson.Obj("kind" -> "context_boundary", "reason" -> "dynamic_external_or_depth_context_unresolved:contributor-scan"))
        else Nil
      ujson.Obj("kind" -> "context_summary") :: (locations ++ elsewhereRows ++ boundaries)
    }
    return summary :: (perSink ++ contextRows)
  }

  val rows = sinkCalls.l.flatMap { sink =>
    // Data flows into the arguments; asking the call node itself finds nothing.
    // `call.argument` includes the RECEIVER at argumentIndex 0 (`db` in `db.execute(...)`), so counting it
    // makes a one-argument interpolated call look like a two-argument bound one -- the exact inversion of the
    // test. Real arguments start at index 1.
    val realArgs = sink.argument.argumentIndexGt(0).l
    // Asked of the REAL arguments, for the same reason arity is counted over them. `call.argument` carries the
    // receiver at index 0, and on a response sink the receiver is the response object itself: `res.end()` takes
    // no data at all, yet `res` is reachable from the request in any handler that captures it, so the flow
    // query answered yes about a call that receives nothing. Measured on NodeGoat, where `res.write(body)` is a
    // real finding and `res.end()` two lines below it was reported identically.
    val flows = if (hasSources) sink.argument.argumentIndexGt(0).reachableByFlows(sourceNodes).l.filter(plausible) else Nil

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
    // With `trace`, each row also carries its SHORTEST path, element by element. Off by default: it exists
    // for adjudication, where a witness naming only its two ends hid that PMPro's object-field findings
    // start at one field and end at another.
    def traced(flow: io.joern.dataflowengineoss.language.Path): ujson.Arr =
      ujson.Arr.from(spliced(flow.elements.l).map { node =>
        val where = node match {
          case c: io.shiftleft.codepropertygraph.generated.nodes.CfgNode => c.method.filename.split("/").last + ":" + c.method.name
          case _                                                          => "?"
        }
        s"$where:${node.lineNumber.getOrElse(-1)} [${node.label}] ${node.code.take(120)}"
      })
    flows
      .map { flow =>
        val path       = spliced(flow.elements.l)
        val elements   = path.map(_.code)
        val sanitized  = (sanitizerNames.nonEmpty || guardNames.nonEmpty) && cleansed(path)
        val sourceKind = sourceKindOf(path.headOption)
        ((sourceKind, elements.headOption.getOrElse("").take(200), sanitized), (elements.size, flow))
      }
      .groupBy(_._1)
      .toList
      .sortBy(_._1)
      .map { case ((sourceKind, source, sanitized), grouped) =>
        val paths = grouped.map { case (key, (size, _)) => (key, size) }
        val shortest = grouped.minBy(_._2._1)._2._2
        val row = ujson.Obj(
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
        if (traceS == "true") row("trace") = traced(shortest)
        row
      }
  }

    // What this question ENUMERATED in scope, independent of what it traced. A flow row proves a
    // path exists; the absence of one cannot distinguish an operation that is not present from an
    // operation no traced path reached. Change comparison needs that distinction to establish that
    // a change introduced an operation, and reachability is deliberately bounded, so the two can
    // never be separated from flow rows alone. The completion marker is what makes an EMPTY
    // inventory meaningful: without it, a scope that was never enumerated and a scope with no such
    // operation look identical. No new sink inference, alias resolution or fact is introduced here.
    val inventory = sinkCalls.l.map { sink =>
      ujson.Obj(
        "kind"            -> "operation_inventory",
        "inventory"       -> sink.code.take(200),
        "inventoryFile"   -> sink.method.filename,
        "inventoryLine"   -> sink.lineNumber.getOrElse(-1).toString,
        "inventoryMethod" -> sink.method.name
      )
    }

    // The enumeration's own basis, because a consumer cannot infer it. A file- or nesting-scoped
    // question walks calls structurally, so an unresolved call destination cannot remove one from
    // the scope and the inventory is complete regardless of reachability. Following the call graph
    // makes the reachable set the scope, so the same unresolved destination can shrink what was
    // enumerated. Only the first kind can support absence under bounded reachability.
    val inventoryScope = if (function.nonEmpty && depth > 0) "reachability" else "structural"
    rows ++ inventory ++ List(
      ujson.Obj("kind" -> "operation_inventory_complete", "operations" -> inventory.size, "scope" -> inventoryScope)
    )
  }

  if (requestsJson.nonEmpty) {
    val parsed = ujson.read(requestsJson).obj
    // STREAMED: the census first, then one line per request as it is answered, flushed as it goes. What
    // this buys is what a kill keeps. Built as one object and printed at the end, a batch killed at its
    // ceiling lost every answer it had finished -- 116 requests at 300 s, then eight JVM starts to ask them
    // all again. Printed as it goes, the same kill keeps everything that finished, the driver harvests it,
    // and only the unfinished requests are asked again. The fence is unchanged; the driver reads both forms.
    val census = ujson.Arr(ujson.Obj("methods" -> cpg.method.size.toString, "files" -> cpg.file.size.toString, "file_names" -> ujson.Arr.from(cpg.file.name.l)))
    println("---OUSAST-CPG-BEGIN---")
    println(ujson.write(ujson.Obj("__census__" -> census)))
    System.out.flush()
    parsed.foreach { case (id, req) =>
      // What THIS answer cost, measured where it is spent. The driver sizes its portions from it, learns the
      // fixed start as the wall time the answers do not account for, and -- when a portion is killed -- knows
      // exactly which request was running, because every one before it reported its own time. A per-portion
      // wall clock cannot tell one 90 s request from thirty 3 s ones, and fitting a single rate to both
      // collapsed the sizer to three sink visits per JVM start on the plugin.
      val started = System.nanoTime()
      def field(name: String): String = req.obj.get(name).map(_.str).getOrElse("")
      // Opt-in heartbeat for the trace runner's per-question process watchdog.
      // Killing the JVM preserves completed streamed rows without unsafe query threads.
      if (field("questionDeadline").nonEmpty) {
        println(ujson.write(ujson.Obj("__question__" -> id)))
        System.out.flush()
      }
      val paramSrc = req.obj.get("parameterSources").map(_.str).getOrElse("false")
      val fieldParamSrc = req.obj.get("fieldParameterSources").map(_.str).getOrElse(paramSrc)
      val fieldSrc = req.obj.get("fieldSources").map(_.str).getOrElse("true")
      val evidence = req.obj.get("evidenceOnly").map(_.str).getOrElse("false")
      val rows = ujson.Arr(
        rowsFor(
          field("sources"),
          field("sinks"),
          field("sanitizers"),
          // Repository-wide, so the driver sends them ONCE as a top-level parameter rather than repeating
          // them in every request. The per-request form is still honoured for the tests and the single
          // -region path.
          if (field("hookCallbacks").nonEmpty) field("hookCallbacks") else hookCallbacks,
          if (field("dispatchApply").nonEmpty) field("dispatchApply") else dispatchApply,
          if (field("dispatchValue").nonEmpty) field("dispatchValue") else dispatchValue,
          field("function"),
          paramSrc,
          fieldParamSrc,
          fieldSrc,
          evidence,
          field("file"),
          field("callDepth"),
          field("boundedSinks"),
          field("contextEvidence"),
          if (field("contextFilter").nonEmpty) field("contextFilter") else contextFilter,
          if (field("contextPaths").nonEmpty) field("contextPaths") else contextPaths,
          field("trace"),
          field("fixedOrigin"),
          field("originAnchors"),
          field("quotedSanitizers"),
          field("guards")
        ): _*
      )
      println(ujson.write(ujson.Obj("id" -> id, "rows" -> rows, "ms" -> ((System.nanoTime() - started) / 1000000L).toDouble)))
      System.out.flush()
    }
    // The census rides the stream as its FIRST line rather than costing its own invocation, because JVM
    // startup is what this whole batching design exists to avoid -- and first because a frontend that fails
    // every file still exits 0 with an empty graph, and the driver must see that even when the process is
    // killed before any request answers.
  } else {
    println("---OUSAST-CPG-BEGIN---")
    println(
      ujson.write(ujson.Arr(rowsFor(sources, sinks, sanitizers, hookCallbacks, dispatchApply, dispatchValue, function, parameterSources, parameterSources, fieldSources, evidenceOnly, file, callDepth, boundedSinks, traceS = trace): _*))
    )
  }
  println("---OUSAST-CPG-END---")
}
