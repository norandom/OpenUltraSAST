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
// It also reports two facts about the INSTRUMENT that were each, once, wrong for a day without anything
// saying so (contributor-scan 5.13): which overlays the graph carries, because a graph without its
// dataflow layer saved has it recomputed by every query batch; and the heap the worker JVM actually got,
// because `-J-Xmx` reaches only the launcher and the configured heap governed nothing until that was seen.
//
// Parameters: cpgFile.
// Output: fenced JSON {files, methods, overlays, maxHeapMB}.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println("---OUSAST-CPG-BEGIN---")
  println(
    ujson.write(
      ujson.Obj(
        "files"     -> cpg.file.size.toString,
        "methods"   -> cpg.method.size.toString,
        "overlays"  -> cpg.metaData.overlays.l.mkString(","),
        "maxHeapMB" -> (Runtime.getRuntime.maxMemory / 1048576).toString
      )
    )
  )
  println("---OUSAST-CPG-END---")
}
