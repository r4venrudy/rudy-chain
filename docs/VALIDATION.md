# Validation

Run from the repository root with the .NET 10 SDK:

```sh
dotnet build tests/Rudy.Chain.Tests -c Release
dotnet run --project tests/Rudy.Chain.Tests -c Release --no-build -- .
dotnet pack src/Rudy.Chain.Cli -c Release -o artifacts
dotnet tool install Rudy.Chain.Tool --version 0.1.0 --tool-path .tools --add-source artifacts --configfile NuGet.Config
```

The regression runner is a standalone C# console program so tests also build and
run without third-party packages. Use `dotnet run` as documented; `dotnet test`
does not execute this runner. Any failed assertion returns a nonzero exit code.

Checks include:

- Shortest paths and reverse dependents through branching and cyclic graphs.
- SCCs, self-loops and 100 seeded random 12-node graphs checked against an
  independent Floyd–Warshall transitive-closure oracle.
- A 10,000-node chain to exercise iterative traversal at the component limit.
- Duplicate keys/refs/edges, unknown targets, malformed hashes, unsupported
  graphs, missing roots, oversized/deep JSON and strict policy input.
- Ref-renaming invariance, duplicate variants, edge-only differences and unknown
  graph-record changes across releases.
- Real CLI subprocesses, JSON/SARIF outputs, exit thresholds and diagnostics.

Local validation on Windows on 2026-10-16 with .NET SDK 10.0.401 / runtime 10.0.12:
**57/57 regression checks passed**, Release build completed with zero warnings
and zero errors, and `dotnet format --verify-no-changes` passed. The packaged tool
was installed from its local `.nupkg` and exercised against the synthetic examples.
These are local results; the live workflow records the platform CI outcomes.

The CI
workflow runs the same tests on three operating systems, then tests installation
and execution of the packaged tool. Platform support claims should be checked
against the corresponding successful GitHub Actions run.

Examples contain no real dependency hashes or discovered vulnerabilities. No live
targets, external vulnerability services, credentials or private inventories are
used by the regression runner.
