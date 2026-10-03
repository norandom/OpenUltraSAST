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

@main def exec(
    cpgFile: String,
    settings: String = "",
    function: String = "",
    file: String = "",
    requests: String = "",
    requestsFile: String = "",
    contextEvidence: String = ""
) = {
  importCpg(cpgFile)

  // The batch arrives as a FILE. A single command-line argument is capped at 128KB on Linux and a
  // repository's requests are megabytes, so passing them as `--param requests=` failed with E2BIG and the
  // driver read the empty result as "no rows". `requests` is kept for the single-request forms and the tests.
  val requestsJson =
    if (requestsFile.nonEmpty) scala.io.Source.fromFile(requestsFile).mkString
    else requests

  def split(raw: String): List[String] = raw.split(",").map(_.trim).filter(_.nonEmpty).toList

  def rowsFor(settingsS: String, functionS: String, fileS: String, contextS: String = ""): List[ujson.Obj] = {
  val names = split(settingsS)
  val function = functionS

  // A dotted spec matches on its trailing segment, which is how the call is named in the graph -- but the
  // qualification has to matter, or the segment alone claims every unrelated call that ends the same way.
  // `marked.setOptions` would otherwise match an editor's `setOptions` and `nunjucks.configure` any
  // `configure` at all. dominance.sc carries this fix and the reason for it; the setting matcher had never
  // been given the same treatment, and it became load-bearing when the template engines joined the table.
  def matches(name: String, code: String): Boolean =
    names.exists { n =>
      if (name == n) true
      else {
        val parts = n.split("\\.")
        parts.length > 1 && name == parts.last && parts.init.forall(q => code.contains(q))
      }
    }

  val calls = {
    // CPS-IT/mailqueue Extension::KEY has a null .method; exclude methodless calls before attribution.
    val all = cpg.call.filter(c => Option(c.method).nonEmpty && matches(c.name, c.code)).l
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

    // Change-attribution context for THIS family, describing the scope this query actually used.
    // Configuration asks which settings a file declares, so the scope is that file's own methods,
    // and the ones holding a matched setting are what the claim is about. It is not taint's
    // reachability projection and not dominance's sibling comparison; each family's context has to
    // describe its own query or it is describing work nobody did.
    def contextRowsFor(): List[ujson.Obj] = {
      def location(m: io.shiftleft.codepropertygraph.generated.nodes.Method, kind: String): ujson.Obj =
        ujson.Obj("kind" -> "context_method", "path" -> m.filename, "function" -> m.name,
          "startLine" -> m.lineNumber.getOrElse(-1), "endLine" -> m.lineNumberEnd.getOrElse(-1),
          "relationship" -> kind)
      val scoped = {
        val all = cpg.method.filterNot(_.isExternal).l
        val inFile = if (fileS.isEmpty) all else all.filter(_.filename.endsWith(fileS))
        if (function.isEmpty) inFile else inFile.filter(_.name == function)
      }
      val settingIds = calls.map(_.method.id).toSet
      val located = scoped.map(m => location(m, if (settingIds.contains(m.id)) "setting" else "sibling"))
      // A question naming a function this file does not define is not the same as a file with no
      // methods at all, and saying so is the difference between a reader knowing what to look at
      // and reading "scope empty".
      val boundaries =
        if (function.nonEmpty && scoped.isEmpty)
          List(ujson.Obj("kind" -> "context_boundary", "reason" -> "context_function_unresolved:contributor-scan", "function" -> function))
        else if (scoped.isEmpty)
          List(ujson.Obj("kind" -> "context_boundary", "reason" -> "context_scope_empty:contributor-scan"))
        else Nil
      ujson.Obj("kind" -> "context_summary") :: (located ++ boundaries)
    }

    if (contextS == "true") rows ++ contextRowsFor() else rows
  }

  println("---OUSAST-CPG-BEGIN---")
  if (requestsJson.nonEmpty) {
    val parsed = ujson.read(requestsJson).obj
    val answers = parsed.map { case (id, req) =>
      def field(name: String): String = req.obj.get(name).map(_.str).getOrElse("")
      id -> ujson.Arr(rowsFor(field("settings"), field("function"), field("file"), field("contextEvidence")): _*)
    }
    // A census of the graph, under a key no request id can collide with (ids are numbers). A frontend can
    // fail every file and STILL exit 0 with a valid, empty CPG -- `joern-parse` does not even propagate the
    // per-file warnings -- so "no rows" and "no graph" are indistinguishable to the driver without this.
    // It rides the batch rather than costing its own invocation, because JVM startup is what this whole
    // batching design exists to avoid.
    val census = ujson.Arr(ujson.Obj("methods" -> cpg.method.size.toString, "files" -> cpg.file.size.toString, "file_names" -> ujson.Arr.from(cpg.file.name.l)))
    println(ujson.write(ujson.Obj.from(answers.toSeq :+ ("__census__" -> census))))
  } else {
    println(ujson.write(ujson.Arr(rowsFor(settings, function, file, contextEvidence): _*)))
  }
  println("---OUSAST-CPG-END---")
}
