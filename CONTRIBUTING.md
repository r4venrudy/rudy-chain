# Contributing

Use the .NET 10 SDK and the build/test commands in README.md. Keep the core free
of third-party runtime dependencies. Add a regression for a meaningful behavior
change, and update docs/CONTRACT.md if input or output semantics change.

Useful contributions include real, redistributable component-only CycloneDX
fixtures, performance measurements with disclosed workloads, importer edge cases,
and clearer graph explanations. Remove private inventory data before sharing.

Run `dotnet format tests/Rudy.Chain.Tests --verify-no-changes` and the regression
runner before submitting. Never claim that an omitted dependency is an empty leaf,
or turn metadata observations into unsupported vulnerability assertions.
