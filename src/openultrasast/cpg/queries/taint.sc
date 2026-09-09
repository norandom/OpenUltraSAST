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
//   callDepth (optional: how many call-graph levels below the labeled method may hold a sink)
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
    parameterSources: String = "false",
    requests: String = ""
) = {
  importCpg(cpgFile)

  def split(raw: String): List[String] = raw.split(",").map(_.trim).filter(_.nonEmpty).toList

  def rowsFor(sourcesS: String, sinksS: String, sanitizersS: String, functionS: String, paramSrc: String, fileS: String, depthS: String): List[ujson.Obj] = {

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
  lazy val reachableMethods: Set[String] =
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
  def parameterNodes =
    if (parameterSources != "true") Iterator.empty
    else if (function.isEmpty) cpg.method.parameter.iterator
    else cpg.method.nameExact(function).parameter.iterator

  def sourceNodes = frameworkSources.l.iterator ++ parameterNodes

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

  def sinkCalls = {
    val all = cpg.call.filter(c => sinkNames.exists(n => sinkMatches(c, n)))
    if (function.isEmpty) {
      // A region with no enclosing function: the file IS the scope.
      if (fileS.isEmpty) all else all.filter(_.method.filename.endsWith(fileS))
    } else if (depth > 0) {
      // Following the call graph means leaving the region's file on purpose, so the file filter would
      // contradict the point. The reachable set is the scope, and the row reports where the sink landed.
      all.filter(c => nestedInLabeled(c.method) || reachableMethods.contains(c.method.fullName))
    } else {
      val inFile = if (fileS.isEmpty) all else all.filter(_.method.filename.endsWith(fileS))
      inFile.filter(c => nestedInLabeled(c.method))
    }
  }

  val rows = sinkCalls.l.flatMap { sink =>
    // Data flows into the arguments; asking the call node itself finds nothing.
    // `call.argument` includes the RECEIVER at argumentIndex 0 (`db` in `db.execute(...)`), so counting it
    // makes a one-argument interpolated call look like a two-argument bound one -- the exact inversion of the
    // test. Real arguments start at index 1.
    val realArgs = sink.argument.argumentIndexGt(0).l
    val flows    = sink.argument.reachableByFlows(sourceNodes).l

    // The SHAPE of the sink call, which is what distinguishes a fix from a bug when the fix is a safe form
    // rather than a sanitizing call: `execute(sql, params)` binds where `execute(sql + x)` interpolates, and
    // `printf("literal", x)` is safe where `printf(userFmt)` is not. The taint path is identical in both, so
    // without these two fields the model entails a pair's fixed side exactly as readily as its vulnerable one.
    val arity       = realArgs.size
    val arg0Literal = realArgs.headOption.map(a => a.isLiteral).getOrElse(false)

    flows.map { flow =>
      val elements = flow.elements.map(_.code).l
      val sanitized = sanitizerNames.nonEmpty && elements.exists(code => mentionsToken(code, sanitizerNames))
      ujson.Obj(
        "sink"            -> sink.code.take(200),
        "sinkLine"        -> sink.lineNumber.getOrElse(-1).toString,
        "sinkMethod"      -> sink.method.name,
        // Where the sink actually is. With callDepth > 0 that need not be the region's own file, and a
        // finding reported against the handler's file when the bug is in another module is unactionable.
        "sinkFile"        -> sink.method.filename,
        "source"          -> elements.headOption.getOrElse("").take(200),
        "sanitized"       -> sanitized,
        "length"          -> elements.size,
        "sinkArity"       -> arity,
        "sinkArg0Literal" -> arg0Literal,
        "inLabeledScope"  -> (function.isEmpty || nestedInLabeled(sink.method) || reachableMethods.contains(sink.method.fullName))
      )
    }
  }

    rows
  }

  println("---OUSAST-CPG-BEGIN---")
  if (requests.nonEmpty) {
    val parsed = ujson.read(requests).obj
    val answers = parsed.map { case (id, req) =>
      def field(name: String): String = req.obj.get(name).map(_.str).getOrElse("")
      val paramSrc = req.obj.get("parameterSources").map(_.str).getOrElse("false")
      id -> ujson.Arr(rowsFor(field("sources"), field("sinks"), field("sanitizers"), field("function"), paramSrc, field("file"), field("callDepth")): _*)
    }
    println(ujson.write(ujson.Obj.from(answers)))
  } else {
    println(ujson.write(ujson.Arr(rowsFor(sources, sinks, sanitizers, function, parameterSources, file, callDepth): _*)))
  }
  println("---OUSAST-CPG-END---")
}
