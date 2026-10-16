# Security boundaries

Rudy Chain reads operator-selected local inventory/policy files and writes stdout
and stderr. It has no runtime network, shell execution, package installation or
remediation features. It does not open paths declared inside an inventory. Build
and installation commands execute the downloaded tool and require a trusted copy.

Inputs are bounded and supported fields are validated, but this preview has not
received an independent security review. Use OS resource limits for processing
hostile inventories in shared infrastructure. A local file path may be a symlink;
the operator chooses the input and its filesystem permissions.

An SBOM may lie or omit dependencies. Hashes, purls, licenses, version labels and
dependency edges are declarations. The tool neither verifies package bytes nor
authenticates a publisher. Unknown edges can conceal paths and reverse impact.
Policy checks are metadata checks, not a vulnerability scan or license compliance
opinion. Output can contain sensitive package names, versions and inventory
metadata; review it before publishing. No automatic secret redaction is claimed.

For suspected vulnerabilities in this tool, use a private GitHub vulnerability
report if enabled, or contact the maintainer through https://rudy.systems before
publishing sensitive details. Ordinary correctness bugs can use GitHub issues.
