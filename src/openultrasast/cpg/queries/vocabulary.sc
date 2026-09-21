// What this repository calls that the ontology does not model (contributor-scan 7.1).
//
// Five of seven families established nothing in the 2026-09 family census, and every one of them failed for
// an ontology reason with the flow engine ready and nothing to aim at: no HTTP client for a server-side
// request forgery, no collection read for an object-reference defect, no WordPress spelling for a
// deserialization. Each was found by investigating one family at a time. This answers the question directly.
//
// It needs no dataflow. The structural pass already walks every call, which is why a census that took three
// investigations can be one query.
//
// What it reports is a CANDIDATE LIST, never an ontology. A name here becomes a fact only when someone
// resolves it to a library API, states the weakness class and records provenance. Adding a name because a
// subject called it is how a general-purpose tool becomes a fixture of its own benchmark.
//
// Parameters: cpgFile, modelled (comma-separated tokens any fact table names), sources (comma-separated
//   source patterns, used only to say whether a call sits in a method that reads untrusted input).
// Output: fenced JSON array of {name, spelling, count, modelled, nearSource, file, line}.
@main def exec(cpgFile: String, modelled: String = "", sources: String = "") = {
  importCpg(cpgFile)

  def split(raw: String): List[String] = raw.split(",").map(_.trim).filter(_.nonEmpty).toList

  val modelledTokens = split(modelled)
  val sourcePatterns = split(sources)

  def boundedPattern(t: String) =
    java.util.regex.Pattern.compile("(?<![A-Za-z0-9_$])" + java.util.regex.Pattern.quote(t) + "(?![A-Za-z0-9_$])")

  val patterns = modelledTokens.map(t => (t, boundedPattern(t)))

  // The callee, which is the only part of a call that names what is being called. Matching a whole node's
  // text is the defect this project has now fixed six times.
  def calleeText(code: String): String = {
    val open = code.indexOf('(')
    val head = if (open < 0) code else code.substring(0, open)
    head.trim.takeRight(120)
  }

  val calls = cpg.call.filterNot(_.name.startsWith("<operator")).l

  // Memoised per method: does this method read something the ontology calls untrusted input? A gap that sits
  // beside a source is worth more attention than one that does not, and that is a ranking hint rather than a
  // claim about any flow.
  val sourceMemo = scala.collection.mutable.Map.empty[String, Boolean]
  def nearSource(c: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean =
    if (sourcePatterns.isEmpty) false
    else
      sourceMemo.getOrElseUpdate(
        c.method.fullName,
        c.method.ast.isCall.exists(x => sourcePatterns.exists(p => x.code.contains(p)))
      )

  def isModelled(c: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean = {
    val callee = calleeText(c.code)
    patterns.exists { case (token, pattern) => c.name == token || pattern.matcher(callee).find() }
  }

  case class Row(name: String, spelling: String, modelledHere: Boolean, near: Boolean, file: String, line: Int)

  val rows = calls.map { c =>
    Row(
      c.name,
      calleeText(c.code),
      isModelled(c),
      nearSource(c),
      c.file.name.l.headOption.getOrElse(""),
      c.lineNumber.getOrElse(-1)
    )
  }

  val grouped = rows.groupBy(_.name).toList.map { case (name, items) =>
    val first = items.head
    ujson.Obj(
      "name" -> name,
      // The commonest qualified spelling, because `get` and `needle.get` are different leads.
      "spelling" -> items.groupBy(_.spelling).toList.maxBy(_._2.size)._1,
      "count" -> items.size,
      "modelled" -> items.exists(_.modelledHere),
      "nearSource" -> items.count(_.near),
      "file" -> first.file,
      "line" -> first.line
    )
  }

  // Unmodelled first and by frequency, because that ordering IS the worklist.
  val ordered = grouped.sortBy(o => (o("modelled").bool, -o("count").num.toInt))

  println("---OUSAST-CPG-BEGIN---")
  println(ujson.write(ujson.Arr(ordered: _*)))
  println("---OUSAST-CPG-END---")
}
