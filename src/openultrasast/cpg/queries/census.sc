// How much of the repository actually made it into the graph (contributor-scan 5.10).
//
// A frontend can log `Failed to process` for a file that is nonetheless present -- measured: a build
// reporting two drops produced a graph holding both of its files and all 139 methods, byte-identical in
// size to a clean one. So the warning is a symptom to investigate, never a verdict, and the only thing that
// settles whether a graph is deficient is the graph.
//
// This matters because acting on the warning alone is destructive: it makes the driver split a repository
// into shards that cannot see each other's flows, and a two-file WordPress pair lost its CVE that way.
//
// Parameters: cpgFile.
// Output: fenced JSON {files, methods}.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println("---OUSAST-CPG-BEGIN---")
  println(ujson.write(ujson.Obj("files" -> cpg.file.size.toString, "methods" -> cpg.method.size.toString)))
  println("---OUSAST-CPG-END---")
}
