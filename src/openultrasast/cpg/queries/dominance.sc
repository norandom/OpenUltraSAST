// Guard dominance for the absence families (model-grounded-detection Req 6.2).
//
// An access-control bug is the ABSENCE of a guard: there is no flow to follow and no crash to reproduce.
// What the model can establish is a consistency violation -- an obligated operation that no discharging guard
// governs, in a file where its siblings are governed by one.
//
// "Governed" is not one relation, because a guard discharges an obligation in three different shapes, and
// asking pure CFG dominance of the operation gets two of them wrong:
//
//   1. identity constraint   the guard is INSIDE the operation's own arguments
//                            Note.query.filter_by(owner_id = current_user.id)
//   2. identity branch       the method branches on identity, and the denial is controlled by that condition
//                            note = ...filter_by(id=nid); if note.owner_id != current_user.id: abort(403)
//                            (measured: abort(403).controlledBy == [note.owner_id != current_user.id])
//   3. dominating guard      a call naming a discharger that dominates the operation -- a check before it
//
// Shape 2 is why `controlledBy` is used rather than `dominatedBy`: the ownership check runs AFTER the fetch,
// so it never dominates the operation, but it does control whether the value escapes.
//
// Parameters: cpgFile, operations, dischargers, function (optional; reported, never used to filter, because
// the sibling comparison needs the file's other operations), file (optional: the source file the region
// belongs to), operationRequires and dischargersByKind (optional JSON, see below).
//
// A discharger only discharges the obligation it is a discharger OF. The facts say `orm-read` requires an
// identity_constraint or an ownership_check, and that `token_validator` is a path_guard; pooling them made
// authenticating the caller discharge an object-level obligation, so a handler that authenticates and then
// looks a record up by a PATH parameter read as fully guarded. `operationRequires` maps an operation call to
// the kinds that would discharge it and `dischargersByKind` maps a kind to its tokens; when both are absent
// the flat list is used, which is the committed single-request behaviour.
//
// Output: a fenced JSON array of {operation, opLine, opMethod, dominatingGuards}.

// BATCHED, like taint.sc: `requests` is {id: {operations, dischargers, function}} and the output is
// {id: [row, ...]}. One JVM start answers a whole scan. The single-request form is kept so the committed
// measurements remain reproducible against the same call shape.

@main def exec(
    cpgFile: String,
    operations: String = "",
    dischargers: String = "",
    function: String = "",
    file: String = "",
    operationRequires: String = "",
    dischargersByKind: String = "",
    requests: String = ""
) = {
  importCpg(cpgFile)

  def split(raw: String): List[String] = raw.split(",").map(_.trim).filter(_.nonEmpty).toList

  def parseMap(raw: String): Map[String, List[String]] =
    if (raw.isEmpty) Map.empty
    else ujson.read(raw).obj.map { case (k, v) => k -> v.arr.map(_.str).toList }.toMap

  def rowsFor(
      operationsS: String,
      dischargersS: String,
      functionS: String,
      fileS: String,
      requiresS: String,
      byKindS: String
  ): List[ujson.Obj] = {

  val opNames     = split(operationsS)
  val guardTokens = split(dischargersS)
  val function    = functionS

  // Word-boundary matching, never substring. A discharger token like `user` matched as a substring hits
  // `users` inside "SELECT * FROM users WHERE id = ?", marking a textbook IDOR as guarded -- a silent false
  // negative on the one family this arbiter exists for.
  val requiresByOp = parseMap(requiresS)
  val tokensByKind = parseMap(byKindS)

  // Word-boundary matching, never substring: a token like `user` matched as a substring hits `users` inside
  // "SELECT * FROM users WHERE id = ?", marking a textbook IDOR as guarded.
  //
  // But the boundary only applies where there IS a word character to bound. `['sub']` begins with `[`, and
  // the character before it in `resp['sub']` is `p` -- so an unconditional lookbehind made every identity
  // token that starts with punctuation unmatchable, and the identity constraint that distinguishes a
  // correct lookup from an IDOR could never be seen.
  def boundedPattern(token: String): java.util.regex.Pattern = {
    val before = if (token.headOption.exists(c => c.isLetterOrDigit || c == '_')) "(?<![A-Za-z0-9_])" else ""
    val after = if (token.lastOption.exists(c => c.isLetterOrDigit || c == '_')) "(?![A-Za-z0-9_])" else ""
    java.util.regex.Pattern.compile(before + java.util.regex.Pattern.quote(token) + after)
  }

  def mentions(code: String, tokens: List[String]): Boolean =
    tokens.exists(g => boundedPattern(g).matcher(code).find())

  def mentionsGuard(code: String): Boolean = mentions(code, guardTokens)

  // The tokens that can discharge THIS operation, rather than every token that can discharge anything.
  def guardsFor(name: String, code: String): List[String] =
    if (requiresByOp.isEmpty || tokensByKind.isEmpty) guardTokens
    else {
      val kinds = opNames
        .filter(n => name == n || (n.split("\\.").length > 1 && name == n.split("\\.").last && n.split("\\.").init.forall(code.contains)))
        .flatMap(n => requiresByOp.getOrElse(n, Nil))
        .distinct
      if (kinds.isEmpty) guardTokens else kinds.flatMap(k => tokensByKind.getOrElse(k, Nil)).distinct
    }

  // Match by CALL NAME, never by code containment: the frontend desugars `Note.query.filter_by(x).first()`
  // into a chain of temporaries, and matching on code yields four or five rows for one operation -- some of
  // them the bare `tmp1.filter_by` receiver, which carries none of the guards the real call does. A `leaky`
  // verdict computed over those extra rows would flag a guarded operation. A dotted spec (`query.get`)
  // matches on its trailing segment, which is how the call is named in the graph.
  //
  // But the trailing segment ALONE is not enough, and on a repository it is catastrophic: `query.get` ends
  // in `get`, so it matched `request.headers.get('Authorization')` and `request_data.get('username')` --
  // ordinary dictionary access read as a protected database operation. Four of seven false positives on the
  // first repository measured came from exactly that, including three handlers that do call an
  // authorization guard. A qualified token means the qualification matters, so the receiver must appear
  // too; the desugared chain still carries it.
  def matchesOperation(name: String, code: String): Boolean =
    opNames.exists { n =>
      if (name == n) true
      else {
        val parts = n.split("\\.")
        parts.length > 1 && name == parts.last && parts.init.forall(q => code.contains(q))
      }
    }

  // Scoped to the region's own file. `delete_user` exists in both the API handler and the model of the
  // repository this was measured on, and unscoped rows attributed the model's unguarded query to the
  // handler. The sibling comparison is a statement about a FILE contradicting itself, which is what the
  // rung's justification says, so the file is also the right scope for it.
  val opCalls = {
    val all = cpg.call.filter(c => matchesOperation(c.name, c.code)).l
    if (fileS.isEmpty) all else all.filter(_.method.filename.endsWith(fileS))
  }

  val rows = opCalls.map { op =>
    val method = op.method

    val applicable = guardsFor(op.name, op.code)

    // 1. identity constraint: a discharger inside the operation's own arguments.
    val inArguments = op.argument.code.l.filter(c => mentions(c, applicable))

    // 2. identity branch: a control structure in this method whose condition names a discharger. The denial
    //    it guards need not dominate the operation -- it controls whether the fetched value escapes.
    val inCondition = method.controlStructure.condition.code.l.filter(c => mentions(c, applicable))

    // 3. dominating guard: a call naming a discharger that actually dominates the operation.
    val dominating = op.dominatedBy.isCall.code.l.filter(c => mentions(c, applicable))

    val guards = (inArguments ++ inCondition ++ dominating).distinct.map(_.take(120))

    ujson.Obj(
      "operation"        -> op.code.take(200),
      "opLine"           -> op.lineNumber.getOrElse(-1).toString,
      "opMethod"         -> method.name,
      "dominatingGuards" -> ujson.Arr(guards.map(ujson.Str(_)): _*)
    )
  }

    rows
  }

  println("---OUSAST-CPG-BEGIN---")
  if (requests.nonEmpty) {
    val parsed = ujson.read(requests).obj
    val answers = parsed.map { case (id, req) =>
      def field(name: String): String = req.obj.get(name).map(_.str).getOrElse("")
      id -> ujson.Arr(
        rowsFor(
          field("operations"),
          field("dischargers"),
          field("function"),
          field("file"),
          field("operationRequires"),
          field("dischargersByKind")
        ): _*
      )
    }
    println(ujson.write(ujson.Obj.from(answers)))
  } else {
    println(ujson.write(ujson.Arr(rowsFor(operations, dischargers, function, file, operationRequires, dischargersByKind): _*)))
  }
  println("---OUSAST-CPG-END---")
}
