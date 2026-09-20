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
// Output: a fenced JSON array of {operation, opLine, opMethod, opFile, dominatingGuards}.

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
    documentShape: String = "",
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

  def parseMap(raw: String): Map[String, List[String]] =
    if (raw.isEmpty) Map.empty
    else ujson.read(raw).obj.map { case (k, v) => k -> v.arr.map(_.str).toList }.toMap

  def rowsFor(
      operationsS: String,
      dischargersS: String,
      functionS: String,
      fileS: String,
      requiresS: String,
      byKindS: String,
      shapeS: String,
      contextS: String = ""
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
  // Calls whose obligation depends on the ARGUMENT rather than the name. `find` is the commonest collection
  // read there is, and also `Array.prototype.find` and jQuery's `.find`, so the name alone cannot carry it.
  //
  // Measured on one WordPress plugin's shipped assets, where 88 calls are named `find`:
  //
  //   70  a jQuery selector          `this.notice.find('.processed')`            LITERAL
  //   13  an array predicate         `datasets.find(ds => ds.label === x)`       METHOD_REF
  //    5  a selector built at run time  ``el.find(`option[value="${v}"]`)``      CALL, an operator
  //    0  a collection read
  //
  // and on NodeGoat, where all three `find` calls are collection reads: two object literals and one builder
  // call. So the shapes separate cleanly, and each exclusion is a measured class rather than a guess:
  // a method reference is a predicate, a literal is a selector, and an operator call is a string being built.
  // A bare IDENTIFIER is deliberately NOT claimed -- `col.find(query)` and `arr.find(pred)` are the same shape
  // and neither repository measured has one, so it is a stated false negative rather than an unmeasured risk.
  val shapeNames = split(shapeS)

  def isQueryDocument(c: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean = {
    val real = c.argument.argumentIndexGt(0).l
    real.headOption match {
      case None       => true // `col.find()` reads the whole collection, which is the obligation at its widest
      case Some(node) =>
        node.label match {
          case "METHOD_REF" => false
          case "LITERAL"    => false
          case "IDENTIFIER" => false
          case "CALL"       => !node.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.Call].name.startsWith("<operator")
          case _            => true // an object literal, which jssrc2cpg gives as a BLOCK
        }
    }
  }

  def matchesOperation(name: String, code: String): Boolean =
    opNames.exists { n =>
      if (name == n) true
      else {
        val parts = n.split("\\.")
        parts.length > 1 && name == parts.last && parts.init.forall(q => code.contains(q))
      }
    }

  def isOperation(c: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean =
    matchesOperation(c.name, c.code) && (!shapeNames.contains(c.name) || isQueryDocument(c))

  // Scoped to the region's own file. `delete_user` exists in both the API handler and the model of the
  // repository this was measured on, and unscoped rows attributed the model's unguarded query to the
  // handler. The sibling comparison is a statement about a FILE contradicting itself, which is what the
  // rung's justification says, so the file is also the right scope for it.
  val allOperations = cpg.call.filter(isOperation).l
  val opCalls = if (fileS.isEmpty) allOperations else allOperations.filter(_.method.filename.endsWith(fileS))

  // ---- The module boundary an application puts between its route and its query --------------------------
  //
  // Measured on NodeGoat: every modelled data operation lives in `app/data/*-dao.js`, none in a route handler
  // file, and the family answered 35 questions there with nothing to say -- the obligation was never raised
  // anywhere the question was asked. Widening the file scope is not the fix, because an unscoped row is
  // exactly what attributed a model's unguarded query to a handler of the same name. The obligation is
  // carried along the call the handler actually writes.
  //
  // How it is followed matters. jssrc2cpg does not resolve `allocationsDAO.getByUserIdAndThreshold(...)` to
  // the DAO's body: the callee is an EXTERNAL stub with no code and no filename. But the stub's fullName
  // records where the member was written -- `app/data/allocations-dao.js::program:AllocationsDAO:getByUser...`
  // -- so the implementation is reached by the graph's own provenance rather than by guessing a name across
  // the repository, which is the false positive this scope was closed to avoid.
  def stubTarget(fullName: String): Option[(String, String)] = {
    val idx = fullName.indexOf("::program:")
    val member = fullName.substring(fullName.lastIndexOf(':') + 1)
    if (idx <= 0 || member.isEmpty) None else Some((fullName.substring(0, idx), member))
  }

  def spans(outer: io.shiftleft.codepropertygraph.generated.nodes.Method, inner: io.shiftleft.codepropertygraph.generated.nodes.Method): Boolean =
    outer.filename == inner.filename &&
      inner.lineNumber.getOrElse(-1) >= outer.lineNumber.getOrElse(0) &&
      inner.lineNumberEnd.getOrElse(-1) <= outer.lineNumberEnd.getOrElse(Int.MaxValue)

  // The method a MEMBER NAME is written as, in one file. A handler or a DAO method written
  // `this.getUserById = (userId, callback) => {}` is a `<lambda>` in the graph, and the assignment puts the
  // lambda's first line on itself -- which is how the written name and the graph's method are joined without
  // a repository-wide name lookup. A language that gives its functions real names (every Python handler this
  // family already answers) matches on the first branch and never needs the second.
  val methodsByFile = scala.collection.mutable.Map.empty[String, List[io.shiftleft.codepropertygraph.generated.nodes.Method]]
  def fileMethods(path: String): List[io.shiftleft.codepropertygraph.generated.nodes.Method] =
    methodsByFile.getOrElseUpdate(path, cpg.method.filterNot(_.isExternal).filter(_.filename.endsWith(path)).l)

  def writtenAs(path: String, member: String): List[io.shiftleft.codepropertygraph.generated.nodes.Method] = {
    val inFile = fileMethods(path)
    val named = inFile.filter(_.name == member)
    if (named.nonEmpty) named
    else {
      val prefixes = List("this." + member, member, "const " + member, "let " + member, "var " + member)
      val lines = inFile
        .flatMap(_.ast.isCall.nameExact("<operator>.assignment").l)
        .filter(a => prefixes.exists(p => a.code.startsWith(p + " =") || a.code.startsWith(p + "=")))
        .flatMap(_.lineNumber)
        .toSet
      inFile.filter(m => m.lineNumber.exists(lines.contains))
    }
  }

  def operationsWithin(path: String, member: String): List[io.shiftleft.codepropertygraph.generated.nodes.Call] = {
    val holders = writtenAs(path, member)
    if (holders.isEmpty) Nil
    else allOperations.filter(op => op.method.filename.endsWith(path) && holders.exists(h => h.id == op.method.id || spans(h, op.method)))
  }

  // One named call out of the scoped file, not a transitive walk. The claim is about the call this handler
  // WRITES: a deeper walk would attribute a helper's helper's query to a handler that never mentions it, and
  // the witness could no longer name the two sites a reader has to open.
  val carried: List[(io.shiftleft.codepropertygraph.generated.nodes.Call, io.shiftleft.codepropertygraph.generated.nodes.Call)] =
    if (fileS.isEmpty) Nil
    else
      fileMethods(fileS).flatMap { m =>
        m.call.l.flatMap { via =>
          via.callee.l
            .filter(_.isExternal)
            .flatMap(stub => stubTarget(stub.fullName))
            .distinct
            .filterNot { case (path, _) => path.endsWith(fileS) }
            .flatMap { case (path, member) => operationsWithin(path, member).map(op => (op, via)) }
        }
      }.distinctBy { case (op, via) => (op.id, via.id) }

  // The region asks about a declared function; the graph may hold it as a lambda. Attributing a row to the
  // declared name is what lets the arbiter match at all -- the same query-to-operation identity problem task
  // 12.3 fixed at the scope end, appearing here at the attribution end.
  val labelled = if (function.isEmpty || fileS.isEmpty) Nil else writtenAs(fileS, function)
  def attributedName(m: io.shiftleft.codepropertygraph.generated.nodes.Method): String =
    if (labelled.exists(l => l.id == m.id || spans(l, m))) function else m.name

  // Change-attribution context for THIS family, describing the scope this query actually used.
  // It is deliberately not taint's projection: dominance compares sibling operations across a
  // file, so the file's own methods are the scope, the methods holding a matched operation are
  // what the claim is about, and the methods holding an applicable discharger are what could
  // discharge it. Exporting an entry/callee reachability walk here would describe work this
  // query never performs.
  def contextRowsFor(): List[ujson.Obj] = {
    def location(m: io.shiftleft.codepropertygraph.generated.nodes.Method, kind: String): ujson.Obj =
      ujson.Obj("kind" -> "context_method", "path" -> m.filename, "function" -> m.name,
        "startLine" -> m.lineNumber.getOrElse(-1), "endLine" -> m.lineNumberEnd.getOrElse(-1),
        "relationship" -> kind)
    val scoped =
      if (fileS.isEmpty) cpg.method.filterNot(_.isExternal).l
      else cpg.method.filterNot(_.isExternal).filter(_.filename.endsWith(fileS)).l
    val operationIds = opCalls.map(_.method.id).toSet ++ carried.map { case (_, via) => via.method.id }.toSet
    val guardIds = scoped.filter(m => m.ast.isCall.code.l.exists(code => mentionsGuard(code))).map(_.id).toSet -- operationIds
    val rows = scoped.map { m =>
      val kind = if (operationIds.contains(m.id)) "operation" else if (guardIds.contains(m.id)) "guard" else "sibling"
      location(m, kind)
    }
    // A carried obligation makes the claim span two files, so the method holding the operation is part of this
    // question's scope even though it is not in the region's file. Leaving it out would let the module that
    // holds the query change under a claim that depends on it without the change being attributed.
    val carriedRows = carried.map { case (op, _) => location(op.method, "carried_operation") }.distinctBy(row => row.value.toString)
    // An empty scope is reported, never implied: a file the frontend produced no methods for
    // cannot support a statement about that file contradicting itself.
    val boundaries =
      if (scoped.isEmpty) List(ujson.Obj("kind" -> "context_boundary", "reason" -> "context_scope_empty:contributor-scan"))
      else Nil
    ujson.Obj("kind" -> "context_summary") :: (rows ++ carriedRows ++ boundaries)
  }

  // ---- The identity a destructuring spelled away -------------------------------------------------------
  //
  // `const { userId } = req.session` lowers to `_tmp_1 = req.session` and then `userId = _tmp_1.userId`, so by
  // the time the value reaches `dao.getByUserId(userId, ...)` nothing in the graph spells `session.userId` and
  // the constraint the handler really applies is invisible. Measured on NodeGoat: two of three corroborated
  // claims were this, which is correct code being put to a judge.
  //
  // Resolved by walking the method's OWN assignments back from the names the operation is given, rather than
  // by accepting the token anywhere in the handler. What discharges an object-level obligation is that the
  // value PASSED to the operation comes from the authenticated context; a handler that reads the session for
  // logging and keys its query on a path parameter is the bug this family exists for, and it stays unguarded.
  // Bounded at three hops, which is two more than the lowering needs and far short of a dataflow query.
  def definingText(
      method: io.shiftleft.codepropertygraph.generated.nodes.Method,
      names: Set[String],
      hops: Int
  ): List[String] = {
    val assignments = method.ast.isCall.nameExact("<operator>.assignment").l
    var seen = names
    var frontier = names
    var texts = List.empty[String]
    var level = 0
    while (level < hops && frontier.nonEmpty) {
      val defining = assignments.filter(a => frontier.exists(n => a.code.startsWith(n + " =")))
      texts = texts ++ defining.map(_.code)
      val next = defining.flatMap(_.argument.argumentIndexGt(1).ast.isIdentifier.name.l).toSet -- seen
      seen = seen ++ next
      frontier = next
      level += 1
    }
    texts.distinct
  }

  // `via` is the call that carried the obligation here, absent when the operation is in the region's own file.
  def rowFor(op: io.shiftleft.codepropertygraph.generated.nodes.Call, via: Option[io.shiftleft.codepropertygraph.generated.nodes.Call]): ujson.Obj = {
    val method = op.method

    val applicable = guardsFor(op.name, op.code)

    // 1. identity constraint: a discharger inside the operation's own arguments.
    val inArguments = op.argument.code.l.filter(c => mentions(c, applicable))

    // 2. identity branch: a control structure in this method whose condition names a discharger. The denial
    //    it guards need not dominate the operation -- it controls whether the fetched value escapes.
    val inCondition = method.controlStructure.condition.code.l.filter(c => mentions(c, applicable))

    // 3. dominating guard: a call naming a discharger that actually dominates the operation.
    //
    // A CALL, so operators are excluded, and that exclusion is load-bearing rather than tidy. `const { userId }
    // = req.session` lowers to an assignment, and an assignment that dominates the query is a READ of the
    // authenticated context, not a check applied to it. Counting it discharged NodeGoat's memo listing, which
    // reads every memo in the collection and only renders the session's user -- the leak that page exists to
    // demonstrate. What a session read does discharge is decided by clause 5, where the value has to reach the
    // operation's own arguments.
    val dominating = op.dominatedBy.isCall.filterNot(_.name.startsWith("<operator")).code.l.filter(c => mentions(c, applicable))

    // 4. a guard at the CARRIER. When the obligation crossed a module boundary the check that discharges it is
    //    overwhelmingly on this side of it: the handler establishes who is asking and passes the result down.
    //    Reading only the operation's own site would report every correctly guarded handler in the repository.
    val atCarrier = via.toList.flatMap { call =>
      call.argument.code.l.filter(c => mentions(c, applicable)) ++
        call.method.controlStructure.condition.code.l.filter(c => mentions(c, applicable)) ++
        call.dominatedBy.isCall.filterNot(_.name.startsWith("<operator")).code.l.filter(c => mentions(c, applicable))
    }

    // 5. identity that reaches the operation's arguments through a local, which is the shape a destructuring
    //    leaves behind. Asked at the site the arguments are written: the carrier when there is one.
    val site = via.getOrElse(op)
    // A CALLBACK is not a constraint, so its body's names are not the operation's arguments. NodeGoat's memo
    // listing is the measurement: `memosDAO.getAllMemos((err, docs) => ... userId ...)` reads every memo in the
    // collection and only RENDERS the session's user, and taking identifiers from the whole argument subtree
    // credited that render with discharging the obligation. The leak is the point of that page.
    val argumentNames = site.argument.argumentIndexGt(0).filterNot(_.label == "METHOD_REF").ast.isIdentifier.name.l.toSet
    val throughLocals = definingText(site.method, argumentNames, 3).filter(c => mentions(c, applicable))

    val guards = (inArguments ++ inCondition ++ dominating ++ atCarrier ++ throughLocals).distinct.map(_.take(120))
    val attributed = via.map(call => attributedName(call.method)).getOrElse(attributedName(method))

    ujson.Obj(
      "operation"        -> op.code.take(200),
      "opLine"           -> op.lineNumber.getOrElse(-1).toString,
      "opMethod"         -> attributed,
      // Where the operation is. Without it an access-control finding reaches a contributor as
      // `api_views/users.py:?:update_password` -- a location no editor can open.
      "opFile"           -> method.filename,
      // The two sites of a carried obligation: the call a reader would open first, and the operation it
      // reaches. Empty for an operation the region's own file holds, which is the committed shape.
      "viaCall"          -> via.map(_.code.take(120).replace("\n", " ")).getOrElse(""),
      "viaLine"          -> via.flatMap(_.lineNumber).map(_.toString).getOrElse(""),
      "viaFile"          -> via.map(_.method.filename).getOrElse(""),
      "dominatingGuards" -> ujson.Arr(guards.map(ujson.Str(_)): _*)
    )
  }

  val rows = opCalls.map(op => rowFor(op, None)) ++ carried.map { case (op, via) => rowFor(op, Some(via)) }

    if (contextS == "true") rows ++ contextRowsFor() else rows
  }

  println("---OUSAST-CPG-BEGIN---")
  if (requestsJson.nonEmpty) {
    val parsed = ujson.read(requestsJson).obj
    val answers = parsed.map { case (id, req) =>
      def field(name: String): String = req.obj.get(name).map(_.str).getOrElse("")
      id -> ujson.Arr(
        rowsFor(
          field("operations"),
          field("dischargers"),
          field("function"),
          field("file"),
          field("operationRequires"),
          field("dischargersByKind"),
          if (field("documentShape").nonEmpty) field("documentShape") else documentShape,
          field("contextEvidence")
        ): _*
      )
    }
    // A census of the graph, under a key no request id can collide with (ids are numbers). A frontend can
    // fail every file and STILL exit 0 with a valid, empty CPG -- `joern-parse` does not even propagate the
    // per-file warnings -- so "no rows" and "no graph" are indistinguishable to the driver without this.
    // It rides the batch rather than costing its own invocation, because JVM startup is what this whole
    // batching design exists to avoid.
    val census = ujson.Arr(ujson.Obj("methods" -> cpg.method.size.toString, "files" -> cpg.file.size.toString, "file_names" -> ujson.Arr.from(cpg.file.name.l)))
    println(ujson.write(ujson.Obj.from(answers.toSeq :+ ("__census__" -> census))))
  } else {
    println(ujson.write(ujson.Arr(rowsFor(operations, dischargers, function, file, operationRequires, dischargersByKind, documentShape, contextEvidence): _*)))
  }
  println("---OUSAST-CPG-END---")
}
