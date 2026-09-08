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
//   cpgFile, sources, sinks, sanitizers (optional), function (optional: restrict to this enclosing method),
//   parameterSources ("true" to treat the labeled function's parameters as untrusted -- see below)
//
// Output: a fenced JSON array of {sink, sinkLine, sinkMethod, source, sanitized, length}. The fence exists
// because Joern prints a banner, pass logs and a prompt around whatever a script emits.

@main def exec(
    cpgFile: String,
    sources: String,
    sinks: String,
    sanitizers: String = "",
    function: String = "",
    parameterSources: String = "false"
) = {
  importCpg(cpgFile)

  def split(raw: String): List[String] = raw.split(",").map(_.trim).filter(_.nonEmpty).toList

  val sourcePatterns = split(sources)
  val sinkNames      = split(sinks)
  val sanitizerNames = split(sanitizers)

  // A source is any call whose code contains one of the patterns. Matching on `code` rather than a method
  // name keeps `request.args["x"]` (an indexAccess over a fieldAccess) and `req.body.name` both reachable
  // without a per-framework rule for each.
  // Framework sources: a call whose code contains one of the patterns. Matching on `code` rather than a
  // method name keeps `request.args["x"]` (an indexAccess over a fieldAccess) and `req.body.name` both
  // reachable without a per-framework rule for each.
  def frameworkSources = cpg.call.filter(c => sourcePatterns.exists(p => c.code.contains(p)))

  // Parameter sources: the labeled function's own parameters. In a function-level pair the function boundary
  // IS the trust boundary -- the corpus is built so the labeled function's inputs are attacker-controlled --
  // and 39 of this slice's 50 pairs carry no framework token at all. Our flat-IR baseline counted these as
  // sources (`source_kinds: ["parameter"]`), so a comparison against it is only like-for-like with them on.
  // Off by default: outside a labeled function, treating every parameter as untrusted is not sound.
  def parameterNodes =
    if (parameterSources != "true") Iterator.empty
    else if (function.isEmpty) cpg.method.parameter.iterator
    else cpg.method.nameExact(function).parameter.iterator

  def sourceNodes = frameworkSources.l.iterator ++ parameterNodes

  // A sink call: matched by short name (`system`), by leading code (`os.system(...)`), or by resolved
  // full name (`os.py:<module>.system`), so both bare and dotted forms in the spec hit.
  def sinkCalls = {
    val all = cpg.call.filter(c =>
      sinkNames.exists(n => c.name == n || c.code.startsWith(n + "(") || c.code.startsWith(n) || c.methodFullName.contains(n))
    )
    if (function.isEmpty) all else all.filter(_.method.name == function)
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
      val sanitized = sanitizerNames.nonEmpty && elements.exists(code => sanitizerNames.exists(s => code.contains(s)))
      ujson.Obj(
        "sink"            -> sink.code.take(200),
        "sinkLine"        -> sink.lineNumber.getOrElse(-1).toString,
        "sinkMethod"      -> sink.method.name,
        "source"          -> elements.headOption.getOrElse("").take(200),
        "sanitized"       -> sanitized,
        "length"          -> elements.size,
        "sinkArity"       -> arity,
        "sinkArg0Literal" -> arg0Literal
      )
    }
  }

  println("---OUSAST-CPG-BEGIN---")
  println(ujson.write(ujson.Arr(rows: _*)))
  println("---OUSAST-CPG-END---")
}
