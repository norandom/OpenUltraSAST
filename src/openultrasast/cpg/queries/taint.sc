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
//   cpgFile, sources, sinks, sanitizers (optional), function (optional: restrict to this enclosing method)
//
// Output: a fenced JSON array of {sink, sinkLine, sinkMethod, source, sanitized, length}. The fence exists
// because Joern prints a banner, pass logs and a prompt around whatever a script emits.

@main def exec(cpgFile: String, sources: String, sinks: String, sanitizers: String = "", function: String = "") = {
  importCpg(cpgFile)

  def split(raw: String): List[String] = raw.split(",").map(_.trim).filter(_.nonEmpty).toList

  val sourcePatterns = split(sources)
  val sinkNames      = split(sinks)
  val sanitizerNames = split(sanitizers)

  // A source is any call whose code contains one of the patterns. Matching on `code` rather than a method
  // name keeps `request.args["x"]` (an indexAccess over a fieldAccess) and `req.body.name` both reachable
  // without a per-framework rule for each.
  def sourceNodes = cpg.call.filter(c => sourcePatterns.exists(p => c.code.contains(p)))

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
    val flows = sink.argument.reachableByFlows(sourceNodes).l
    flows.map { flow =>
      val elements = flow.elements.map(_.code).l
      val sanitized = sanitizerNames.nonEmpty && elements.exists(code => sanitizerNames.exists(s => code.contains(s)))
      ujson.Obj(
        "sink"       -> sink.code.take(200),
        "sinkLine"   -> sink.lineNumber.getOrElse(-1).toString,
        "sinkMethod" -> sink.method.name,
        "source"     -> elements.headOption.getOrElse("").take(200),
        "sanitized"  -> sanitized,
        "length"     -> elements.size
      )
    }
  }

  println("---OUSAST-CPG-BEGIN---")
  println(ujson.write(ujson.Arr(rows: _*)))
  println("---OUSAST-CPG-END---")
}
