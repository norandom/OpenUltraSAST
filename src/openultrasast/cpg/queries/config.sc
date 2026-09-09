// Security settings and the literal values they are given (model-grounded-detection Req 6.3).
//
// A configuration bug has no flow and no guard: `CORS(app, origins="*")` is dangerous because of the value.
// This query reports each setting call with its arguments split into literals (which the model can evaluate)
// and non-literals (which it cannot -- those become `corroborated`, never silently safe).
//
// Parameters: cpgFile, settings, function (optional), file (optional: restrict to this source file).
//
// `file` matters more than it looks. A region with no enclosing function -- a module of settings, an
// __init__.py -- used to send function="" and match EVERY setting in the repository, and the driver then
// attributed the whole answer to whichever region asked. One `host='0.0.0.0'` in app.py became eight
// identical entailed findings in eight files that do not contain it.
// Output: fenced JSON array of {setting, line, method, args, literalArgs}.

// BATCHED, like taint.sc. Single-request form kept for the committed measurements.

@main def exec(cpgFile: String, settings: String = "", function: String = "", file: String = "", requests: String = "") = {
  importCpg(cpgFile)

  def split(raw: String): List[String] = raw.split(",").map(_.trim).filter(_.nonEmpty).toList

  def rowsFor(settingsS: String, functionS: String, fileS: String): List[ujson.Obj] = {
  val names = split(settingsS)
  val function = functionS

  def matches(name: String): Boolean = names.exists(n => name == n || name == n.split("\\.").last)

  val calls = {
    val all = cpg.call.filter(c => matches(c.name)).l
    val inFile = if (fileS.isEmpty) all else all.filter(_.method.filename.endsWith(fileS))
    if (function.isEmpty) inFile else inFile.filter(_.method.name == function)
  }

  val rows = calls.map { call =>
    // Joern indexes the receiver at 0, positional arguments from 1, and NAMED arguments at -1. A setting is
    // configured overwhelmingly by keyword (`origins="*"`, `secure=False`), so filtering `argumentIndexGt(0)`
    // -- correct when counting arity for the taint shape test -- drops exactly the arguments that matter here
    // and every keyword-configured setting reads as "computed".
    val args = call.argument.filter(_.argumentIndex != 0).l
    ujson.Obj(
      "setting"     -> call.code.take(200),
      "line"        -> call.lineNumber.getOrElse(-1).toString,
      "method"      -> call.method.name,
      "args"        -> ujson.Arr(args.map(a => ujson.Str(a.code.take(80))): _*),
      // A keyword argument (`origins = "*"`) is an assignment-shaped node, so `isLiteral` is false on the
      // argument itself and the literal sits inside it. Collect literals from the argument's SUBTREE, or
      // every keyword-configured setting reads as "computed" and nothing is ever evaluated.
      "literalArgs" -> ujson.Arr(args.flatMap(a => a.ast.isLiteral.code.l).distinct.map(c => ujson.Str(c.take(80))): _*)
    )
  }

    rows
  }

  println("---OUSAST-CPG-BEGIN---")
  if (requests.nonEmpty) {
    val parsed = ujson.read(requests).obj
    val answers = parsed.map { case (id, req) =>
      def field(name: String): String = req.obj.get(name).map(_.str).getOrElse("")
      id -> ujson.Arr(rowsFor(field("settings"), field("function"), field("file")): _*)
    }
    println(ujson.write(ujson.Obj.from(answers)))
  } else {
    println(ujson.write(ujson.Arr(rowsFor(settings, function, file): _*)))
  }
  println("---OUSAST-CPG-END---")
}
