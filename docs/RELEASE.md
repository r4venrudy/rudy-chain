Rudy Chain's first developer preview: offline CycloneDX component graph analysis
and supply-chain metadata policies, implemented in C# / .NET 10.

- Explain shortest declared dependency paths and list reverse dependents.
- Detect cycles with iterative strongly connected component analysis.
- Compare release inventory variants and dependency edges independently of bom-ref labels.
- Report missing metadata, unknown dependency records, digest contradictions and exact deny-list matches.
- Export JSON or SARIF 2.1.0 and fail CI at a chosen policy threshold.

Requires .NET 10. The `.nupkg` installs as a .NET tool from a local package source.
The portable ZIP runs with `dotnet Rudy.Chain.Cli.dll`; see README.md for examples
and SHA256SUMS.txt for download checksums.

Preview boundaries: component-only CycloneDX JSON 1.5–1.7 subset, required root,
opaque license expressions, no CVE feed, publisher authentication, package-byte
verification or runtime reachability claims. All bundled examples are synthetic.
