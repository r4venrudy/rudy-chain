# Input and output contract · v1

## Accepted inventory

UTF-8 JSON (optional UTF-8 BOM), with `bomFormat: CycloneDX` and `specVersion`
`1.5`, `1.6` or `1.7`. The importer does not claim complete schema validation.

- `metadata.component` is required and participates in the graph as its root.
- Every component needs unique nonempty `bom-ref`, `type` and `name` strings.
- `group`, `version`, `purl` and `scope` are optional strings. Explicit null is
  rejected for these supported fields. Values are not inferred or normalized.
- Top-level and nested `components` are flattened. Containment is not an edge.
- `licenses` accepts `{license: {id: ...}}`, `{license: {name: ...}}` or
  `{expression: ...}`. Values are sorted and deduplicated. Expressions are opaque.
- `hashes` accepts string `alg` and `content` fields. SHA-256/384/512 require exact
  64/96/128 hexadecimal characters and are case-normalized. Other algorithms do
  not satisfy the strong-hash requirement. Duplicate algorithms are rejected.
- `dependencies` records contain a unique known `ref` and optional `dependsOn`
  array of unique known component refs. An explicit record with no targets is a
  leaf declaration. A component with no record has **unknown dependencies**.
- Nonempty top-level `services` and nonempty `provides` arrays are rejected.
  Unknown graph targets (including external BOM links) are rejected.
- Composition statements and embedded vulnerability assertions produce notices
  but are not evaluated. Other fields are ignored, not certified.

Duplicate JSON property names are rejected at every depth, including ignored
fields. Invalid UTF-8 is rejected by the JSON parser. Strong hashes are declarations
only: no package files are opened to verify them.

## Limits

| Resource | Limit |
| --- | ---: |
| Inventory bytes | 16,777,216 |
| Policy bytes | 65,536 |
| Components, including root | 10,000 |
| Declared edges | 100,000 |
| JSON depth | 64 |
| JSON values | 500,000 |
| Decoded property name / string length | 8,192 UTF-16 code units |
| Audit finding path | Last 32 refs, with `pathTruncated: true` when truncated |

`why` returns the complete shortest path, bounded by the component count. Graph
traversal and SCC detection are iterative. All references and adjacency lists use
ordinal ordering, giving deterministic tie-breaking between equally short paths.
`impact` excludes the queried component itself, even if part of a cycle. It reports
known reverse dependents, not a claim that unknown graph portions have no impact.

## Rules

| ID | Default level | Observation |
| --- | --- | --- |
| CHAIN001 | warning | No declared SHA-256, SHA-384 or SHA-512 digest |
| CHAIN002 | warning | Missing/blank version |
| CHAIN003 | warning | Missing/blank purl |
| CHAIN004 | warning | No dependency record for a component |
| CHAIN005 | note | No declared root path |
| CHAIN006 | note | A dependency SCC with multiple members, or a self-loop |
| CHAIN007 | error | Exact purl denied by supplied policy |
| CHAIN008 | error | Same purl has differing strong hashes of the same algorithm |
| CHAIN009 | error | Exact whole license value denied by supplied policy |
| CHAIN010 | warning | No license declaration when `requireLicense` is enabled |
| CHAIN011 | error | Exact component type denied by supplied policy |

Cycles and unreachable components can be legitimate inventory structures. Levels
represent policy priority, not vulnerability severity or CVSS. Require flags only
control CHAIN001–004 and CHAIN010; other observations remain enabled. All component scopes are
audited. Deny lists are exact and case-sensitive, with no wildcard, SPDX expression
evaluation, version-range matching or purl normalization. Unknown policy keys,
duplicate keys, null/nonboolean flags and malformed lists are errors.

## Comparison

Package groups use `(type, group, name)`. Every variant in a group is retained;
variant comparison includes version, purl, scope, complete license values and hash
declarations. Duplicate variants are counted. Identity is inventory metadata, not
proof that packages share a publisher or contents.

Edges use `(type, group, name, version, purl)` for both endpoints and collapse
semantically identical alias edges. Digest/license/scope differences are reported
in package changes, not edge identities. `bom-ref` renaming is ignored in the
semantic diff. Root coordinates and unknown-record coordinates are emitted for
both inputs. Moving a root role to an indistinguishable coordinate is not detected.
An absent package group is an inventory difference, not evidence of remediation
or removal from a running deployment.

## Reports and exit codes

Reports carry a versioned `schema` identifier. Input SHA-256 hashes cover the
original bytes, including whitespace and any BOM; these are integrity identifiers,
not signatures. Array ordering is deterministic; reports have no clock fields.

Audit emits a root, counts, SCC groups, notices and findings. A finding path is
empty when no root path is declared. SCC arrays contain members, not necessarily
an ordered route around a cycle. Diff emits structured package variants and edges.

SARIF 2.1.0 emits rules and findings with no invented physical source location.
Result properties retain component ref, input digest and a dependency path.
Fingerprints hash the JSON pair `[ruleId, componentRef]`; they are stable within a
reference scheme, not invariant under `bom-ref` renaming or across unrelated BOMs.

Exit 0: valid completed command below the threshold. Exit 1: audit threshold or optional diff change gate met.
Exit 2: rejected input, bad usage or I/O failure. Errors go to stderr; a rejected
input produces no report on stdout. `--fail-on error` is the default. `warning`
includes error and warning; `none` never rejects a valid report. Diff optionally
accepts `--fail-on-change` to gate semantic inventory changes. Output pipes and filesystem permissions are the operator's concern.

## Extended queries

`summary` emits `rudy-chain/summary/v1`, counts metadata presence, explicit leaves,
known reachability and omitted records, and groups exact type/scope strings.
`leaves` emits `rudy-chain/leaves/v1`; omitted dependency records never count as
leaves. `cycles` emits `rudy-chain/cycles/v1`; SCC members are sets, not routes.
All three include the input digest and coverage notices. Graph queries do not
run policy gates and complete with exit 0 for valid input.

`why --from <ref>` preserves the BOM root and reports the chosen `source`.
`impact --depth N` limits shortest reverse hops to N, from 0 through 10000.
Omitting depth retains full traversal (`maxDepth: null`). Unknown dependencies
can hide additional paths, leaves and cycles at any depth.

`requireLicense` defaults to false. `deniedComponentTypes` defaults to an empty
list and matches exact, case-sensitive type strings for all components.

The optional diff gate ignores byte formatting and reference renaming. It fails
on package/edge changes, a changed root coordinate, or changed unknown-record
coordinates. Exit 1 still includes the complete diff report on stdout.
