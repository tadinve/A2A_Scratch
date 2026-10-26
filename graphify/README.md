# graphify: knowledge graph of this repo

[graphify](https://github.com/safishamsi/graphify) turns the code and docs in this repo into a
knowledge graph: nodes for functions, classes, modules and doc concepts, plus edges for calls,
imports and references. It then groups related nodes into communities and writes a short
report on the result.

Right now we only *use* graphify. Later we'll learn how to build a knowledge graph ourselves
(see [Learning to build one](#learning-to-build-one)).

## Layout

```
graphify/
  README.md            this file
  graphify-out/        everything graphify writes
    graph.html         interactive graph (open in a browser, no server needed)
    GRAPH_REPORT.md    audit report: god nodes, surprising links, communities, questions
    graph.json         raw graph (nodes, edges, communities), GraphRAG-ready
    manifest.json      file hashes from the last run, used by --update
    cost.json          LLM tokens spent per run
    .graphify_labels.json  community names
    cache/             per-file extraction cache (git-ignored)
graphify-out -> graphify/graphify-out   symlink at the repo root
```

The skill and the `graphify` CLI always read and write `./graphify-out`. The symlink at the repo
root points there, so they work without any extra settings. Graphify never scans a folder named
`graphify-out` as input.

## Install (once per machine)

```bash
uv tool install graphifyy          # the PyPI package is "graphifyy" (two y's)
graphify install --platform claude # installs the /graphify skill for Claude Code
```

## Run it

Run these from the repo root in Claude Code:

| Command | When | Cost |
|---|---|---|
| `/graphify` | first build, or a full rebuild | code: free (tree-sitter AST); docs: one subagent read, ~64k tokens for our 8 docs |
| `/graphify --update` | after changing files | free if only code changed; re-reads only the docs that changed |
| `/graphify --cluster-only` | regroup communities without re-extracting | free |
| `/graphify query "How does delegation reach the inventory policy?"` | ask the graph a question | free |

You can also query from the terminal without Claude:

```bash
graphify query "how is a delegation token verified"   # BFS over the graph
graphify path "delegate()" "is_allowed()"             # shortest path between two nodes
graphify explain "authenticate_delegation()"          # one node and its neighbours
graphify update .                                     # code-only re-extract, no LLM
```

After an update, look at the **Graph health** line. Any dangling or missing edges mean the graph
is incomplete. Also check the INFERRED edges in "Surprising Connections": when two modules
define a function with the same name (e.g. `load_config()`), graphify can attach a call to the
wrong one.

## What to commit

Commit `graph.json`, `graph.html`, `GRAPH_REPORT.md`, `manifest.json`, `cost.json` and the
labels, so the graph's history follows the repo day by day. `cache/` and the two sidecars that
hold this machine's absolute paths (`.graphify_python`, `.graphify_root`) are git-ignored.

## Learning to build one

These are the pipeline stages graphify runs (v0.9.95). Each one is a topic to learn and
rebuild ourselves later:

1. **Detect.** Walk the repo, sort files into code, docs, papers, images and video, and skip
   anything sensitive or ignored. (This run skipped `local-implementation-docs/day05-signed-tokens.pptx` as sensitive.)
2. **Structural extraction.** Parse code with tree-sitter into an AST, then emit nodes
   (modules, classes, functions) and edges (`calls`, `imports_from`, `references`). This step
   is deterministic and needs no LLM.
3. **Semantic extraction.** An LLM reads the docs and emits concept nodes and edges. Every edge
   is tagged EXTRACTED (stated in the source), INFERRED (a reasoned guess with a confidence
   score) or AMBIGUOUS.
4. **Merge and build.** Merge the AST and LLM outputs into one NetworkX graph, deduplicating
   nodes by stable IDs (`{path}_{symbol}`).
5. **Community detection.** Leiden (or Louvain as a fallback) groups densely connected nodes.
   Each community gets a cohesion score, and oversized ones are split.
6. **Analysis.** Find god nodes (highest degree), bridge nodes (betweenness centrality) and
   surprising cross-community edges.
7. **Export and query.** Write the JSON, HTML and report. Queries traverse the graph
   breadth-first or depth-first.
8. **Incremental update.** Hash every file, re-extract only what changed, and replace those
   files' nodes in the existing graph.
