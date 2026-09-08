// Taint reachability for one flow family (model-grounded-detection Req 6.1).
//
// The question this answers is the one our flat IR could not: does an untrusted source reach the labeled sink
// *through resolved dataflow*, and is there a sanitizer on that path. Joern's `reachableByFlows` walks the
// PDG, so a value bound three statements upstream — `q = "..." + request.args["x"]; execute(q)` — is found,
// which is exactly the one-hop limit that held our measured entailment at 2.2%.
//
// Parameters (all comma-separated where plural):
//   cpgFile     the built cpg.bin
//   sources     source matchers, e.g. request.args,request.form
//   sinks       sink call names, e.g. execute,os.system
//   sanitizers  sanitizer call names; a flow through one of these is corroborated, not entailed
//   function    optional: restrict sinks to this enclosing method
//
// Output: a fenced JSON array of {sink, sinkLine, sinkMethod, source, sanitized, length}.
// The fence exists because Joern prints a banner and a prompt around whatever a script emits.

@main def exec(cpgFile: String, sources: String, sinks: String, sanitizers: String = "", function: String = "") = {
  importCpg(cpgFile)

  def split(raw: String): List[String] =
    raw.split(",").map(_.trim).filter(_.nonEmpty).toList

  val sourcePatterns    = split(sources)
  val sinkNames         = split(sinks)
  val sanitizerNames    = split(sanitizers)

  // A source is any call or identifier whose code matches one of the source patterns. Matching on `code`
  // rather than on a method name keeps `request.args["x"]` and `req.body.name` both reachable without
  // per-framework special cases.
  def sourceNodes = cpg.call.filter(c => sourcePatterns.exists(p => c.code.contains(p))).l ++
                    cpg.identifier.filter(i => sourcePatterns.exists(p => i.code.contains(p))).l

  // A sink is a call whose name (or full code) names one of the family's sinks, optionally inside `function`.
  def sinkNodes = {
    val all = cpg.call.filter(c => sinkNames.exists(n => c.name == n || c.code.startsWith(n) || c.methodFullName.contains(n))).l
    if (function.isEmpty) all else all.filter(_.method.name == function)
  }

  def isSanitized(flowCode: List[String]): Boolean =
    sanitizerNames.nonEmpty && flowCode.exists(code => sanitizerNames.exists(s => code.contains(s)))

  val rows = sinkNodes.flatMap { sink =>
    val flows = sourceNodes.reachableByFlows(sink).l
    flows.map { flow =>
      val elements = flow.elements.map(_.code).l
      ujson.Obj(
        "sink"       -> sink.code.take(200),
        "sinkLine"   -> sink.lineNumber.getOrElse(-1).toString,
        "sinkMethod" -> sink.method.name,
        "source"     -> elements.headOption.getOrElse("").take(200),
        "sanitized"  -> isSanitized(elements),
        "length"     -> elements.size
      )
    }
  }

  println("---OUSAST-CPG-BEGIN---")
  println(ujson.write(ujson.Arr(rows: _*)))
  println("---OUSAST-CPG-END---")
}
