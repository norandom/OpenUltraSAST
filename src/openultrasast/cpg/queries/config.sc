// Security settings and the literal values they are given (model-grounded-detection Req 6.3).
//
// A configuration bug has no flow and no guard: `CORS(app, origins="*")` is dangerous because of the value.
// This query reports each setting call with its arguments split into literals (which the model can evaluate)
// and non-literals (which it cannot -- those become `corroborated`, never silently safe).
//
// Parameters: cpgFile, settings, function (optional).
// Output: fenced JSON array of {setting, line, method, args, literalArgs}.

@main def exec(cpgFile: String, settings: String, function: String = "") = {
  importCpg(cpgFile)

  def split(raw: String): List[String] = raw.split(",").map(_.trim).filter(_.nonEmpty).toList
  val names = split(settings)

  def matches(name: String): Boolean = names.exists(n => name == n || name == n.split("\\.").last)

  val calls = {
    val all = cpg.call.filter(c => matches(c.name)).l
    if (function.isEmpty) all else all.filter(_.method.name == function)
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

  println("---OUSAST-CPG-BEGIN---")
  println(ujson.write(ujson.Arr(rows: _*)))
  println("---OUSAST-CPG-END---")
}
