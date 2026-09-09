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
// the sibling comparison needs every operation in the CPG).
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
    requests: String = ""
) = {
  importCpg(cpgFile)

  def split(raw: String): List[String] = raw.split(",").map(_.trim).filter(_.nonEmpty).toList

  def rowsFor(operationsS: String, dischargersS: String, functionS: String): List[ujson.Obj] = {

  val opNames     = split(operationsS)
  val guardTokens = split(dischargersS)
  val function    = functionS

  // Word-boundary matching, never substring. A discharger token like `user` matched as a substring hits
  // `users` inside "SELECT * FROM users WHERE id = ?", marking a textbook IDOR as guarded -- a silent false
  // negative on the one family this arbiter exists for.
  def mentionsGuard(code: String): Boolean =
    guardTokens.exists(g => java.util.regex.Pattern.compile("(?<![A-Za-z0-9_])" + java.util.regex.Pattern.quote(g) + "(?![A-Za-z0-9_])").matcher(code).find())

  // Match by CALL NAME, never by code containment: the frontend desugars `Note.query.filter_by(x).first()`
  // into a chain of temporaries, and matching on code yields four or five rows for one operation -- some of
  // them the bare `tmp1.filter_by` receiver, which carries none of the guards the real call does. A `leaky`
  // verdict computed over those extra rows would flag a guarded operation. A dotted spec (`query.get`)
  // matches on its trailing segment, which is how the call is named in the graph.
  def matchesOperation(name: String): Boolean =
    opNames.exists(n => name == n || name == n.split("\\.").last)

  val opCalls = cpg.call.filter(c => matchesOperation(c.name)).l

  val rows = opCalls.map { op =>
    val method = op.method

    // 1. identity constraint: a discharger inside the operation's own arguments.
    val inArguments = op.argument.code.l.filter(mentionsGuard)

    // 2. identity branch: a control structure in this method whose condition names a discharger. The denial
    //    it guards need not dominate the operation -- it controls whether the fetched value escapes.
    val inCondition = method.controlStructure.condition.code.l.filter(mentionsGuard)

    // 3. dominating guard: a call naming a discharger that actually dominates the operation.
    val dominating = op.dominatedBy.isCall.code.l.filter(mentionsGuard)

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
      id -> ujson.Arr(rowsFor(field("operations"), field("dischargers"), field("function")): _*)
    }
    println(ujson.write(ujson.Obj.from(answers)))
  } else {
    println(ujson.write(ujson.Arr(rowsFor(operations, dischargers, function): _*)))
  }
  println("---OUSAST-CPG-END---")
}
