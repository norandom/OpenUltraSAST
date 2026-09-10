// Apply Joern's default overlays ONCE, at build time, and save them into the graph (contributor-scan 5.13).
//
// A frontend writes a raw graph. The call graph, the type layer and the reaching-definitions pass that
// every dataflow question runs on are OVERLAYS, and `importCpg` computes each one the graph lacks every
// time a JVM opens it. `joern-parse` applies them once and saves; a frontend run directly does not. So
// from the day PHP builds went through php2cpg (2026-09-09, 1ce7e9d) every query batch recomputed the whole
// dataflow layer before its first request: 54 s of fixed cost on a 637-file plugin, and on WP Statistics a
// pass that ran the heap out after 21 minutes -- a graph the same tool had entailed CVE-2022-25148 on, an
// hour before the switch, from a joern-parse build.
//
// Measured after: the saved graph reloads in 8 s where the raw one took 64 s, and the request that had
// timed out at 520 s answered in 39 s including the JVM. `joern-parse --overlaysonly` would be the
// obvious tool and is broken in 4.0.623 (NullPointerException in a post-processing step that needs the
// frontend it did not run), so the once is this script.
//
// `save` writes to `workspace/<cpg name>/cpg.bin` under the working directory; the driver moves that over
// the raw graph.
//
// Parameters: cpgFile.
// Output: fenced JSON {files, methods}.
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  save
  println("---OUSAST-CPG-BEGIN---")
  println(ujson.write(ujson.Obj("files" -> cpg.file.size.toString, "methods" -> cpg.method.size.toString)))
  println("---OUSAST-CPG-END---")
}
