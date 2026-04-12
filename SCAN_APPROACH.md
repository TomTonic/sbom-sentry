# extract-sbom Scan Approach

This document explains how extract-sbom processes one delivery file. It
describes the current implementation, not an idealized future design. The goal
is simple: one supplier delivery goes in, one auditable SBOM and one audit
report come out.

For the product overview, see [README.md](README.md). For the formal
requirements, see [DESIGN.md](DESIGN.md). For module-level implementation
details, see [MODULE_GUIDE.md](MODULE_GUIDE.md).

## 1. Key Terms

The document uses a small set of fixed terms.

| Term | Meaning |
|---|---|
| delivery | The input file given to extract-sbom. |
| node | One tracked artifact in the processing tree. Typical examples are `delivery.zip`, `app.tar.gz`, `runtime.jar`, or `setup.msi`. |
| delivery path | The stable logical path of a node inside the original delivery, for example `delivery.zip/app.tar.gz/runtime.jar`. |
| status | The extraction phase decision for a node. The scan phase does not rewrite it. |
| scan target | A node that the scan phase actually sends to Syft. Only nodes with status `extracted` or `syft-native` become scan targets. |
| evidence path | An optional, more specific path that supports a component finding, for example a manifest inside a JAR. |

## 2. Evidence Sources

extract-sbom relies on observed facts from four places:

- the bytes of the original delivery file
- the format detection and extraction results recorded while walking the delivery
- MSI Property table data when the artifact is an MSI package
- Syft package data, including Syft's package locations

Around those facts, extract-sbom adds hashes, delivery paths, statuses, and a
deterministic output order. It does not invent packages, infer vendor intent,
or fill gaps with guesses.

## 3. Two Phases

Processing always runs in two sequential phases.

**Phase 1 — Extraction.** `internal/extract` walks the delivery recursively
and builds the extraction tree. For every file it encounters, it identifies the
format and assigns a status. Container formats that extract-sbom can open are
unpacked under strict safety limits. Formats that Syft understands natively as
intact package formats are marked `syft-native` and left on disk. Everything
else is recorded as a `skipped` leaf. At the end of Phase 1, the tree and all
statuses are final.

**Phase 2 — Scanning.** `internal/scan` sends nodes to Syft based on their
statuses. Only `extracted` and `syft-native` nodes become scan targets. In
Phase 2, extract-sbom first scans all extracted directories in parallel, then
tries to reuse those results for their `syft-native` child nodes where possible,
and finally scans only the remaining `syft-native` nodes that could not be
resolved from a parent directory result.

The two phases are strictly sequential. No extraction happens during scanning
and no scanning happens during extraction.

## 4. Running Example

This section introduces one complete delivery and traces it through both phases.
Every supported archive and package format appears at least once.

### 4.1 The Delivery

The delivery arrives as one file: `vendor-suite-3.2.zip`. It contains a Linux
server component, a Windows fat client and legacy add-on, a webapp patch, and
documentation.

```text
vendor-suite-3.2.zip
├── linux/
│   ├── server-3.2.rpm
│   ├── libssl1.1_1.1.1n-0_amd64.deb
│   ├── apache-tomcat-9.0.98.tar.gz
│   │   ├── lib/
│   │   │   ├── catalina.jar
│   │   │   ├── tomcat-embed-core-9.0.98.jar
│   │   │   └── servlet-api.jar
│   │   └── webapps/
│   │       └── vendor-app.ear
│   └── resources.tgz
│       └── translations/
│           ├── de.properties
│           └── en.properties
├── windows/
│   ├── client-setup.msi
│   │   ├── Program Files/Vendor/FatClient/client.exe
│   │   └── Program Files/Vendor/FatClient/plugins/sign-plugin.ocx
│   ├── prereqs/
│   │   └── vcredist.cab
│   └── legacy-addon/
│       ├── data1.hdr
│       └── data1.cab
├── web/
│   └── webapp-patch-1.2.1.7z
│       └── webapp/
│           ├── index.js                (bare file copy of minimist@0.0.8)
│           └── node_modules/
│               └── minimist/
│                   ├── package.json    (declares minimist version 0.0.8)
│                   └── index.js        (file containing code of minimist@0.0.8)
└── docs/
    └── release-notes.pdf
```

The two `index.js` files in the webapp patch are not the same from Syft's
perspective, even though they contain the same code. Section 4.4 explains why.

### 4.2 Phase 1: Who Extracts What

`internal/extract` processes the delivery depth-first. For each file it
identifies the format first, then acts.

| Node | Tool | Status after Phase 1 |
|---|---|---|
| `vendor-suite-3.2.zip` | extract-sbom — Go `archive/zip` | `extracted` |
| `linux/server-3.2.rpm` | — | `syft-native` — RPM is a Syft-native format |
| `linux/libssl1.1_1.1.1n-0_amd64.deb` | — | `syft-native` — DEB is a Syft-native format |
| `linux/apache-tomcat-9.0.98.tar.gz` | extract-sbom — Go `archive/tar` + `compress/gzip` | `extracted` |
| `lib/catalina.jar` | — | `syft-native` |
| `lib/tomcat-embed-core-9.0.98.jar` | — | `syft-native` |
| `lib/servlet-api.jar` | — | `syft-native` |
| `webapps/vendor-app.ear` | — | `syft-native` |
| `linux/resources.tgz` | extract-sbom — Go `archive/tar` + `compress/gzip` | `extracted` |
| `translations/de.properties` | — | `skipped` — plain file |
| `translations/en.properties` | — | `skipped` — plain file |
| `windows/client-setup.msi` | extract-sbom reads MSI Property table; `7zz` (sandboxed) extracts payload | `extracted`; MSI product metadata recorded |
| `Program Files/.../client.exe` | — | `skipped` — plain file |
| `Program Files/.../sign-plugin.ocx` | — | `skipped` — plain file |
| `windows/prereqs/vcredist.cab` | `7zz` (sandboxed) — Microsoft CAB | `extracted` |
| `windows/legacy-addon/data1.cab` | `unshield` (sandboxed) — InstallShield cabinet | `extracted` |
| `windows/legacy-addon/data1.hdr` | — | `skipped` — InstallShield header file, not itself a container |
| `web/webapp-patch-1.2.1.7z` | `7zz` (sandboxed) | `extracted` |
| `webapp/index.js` | — | `skipped` — plain file, no package manifest |
| `webapp/node_modules/minimist/package.json` | — | `skipped` — plain file, covered by parent directory scan |
| `webapp/node_modules/minimist/index.js` | — | `skipped` — plain file, covered by parent directory scan |
| `docs/release-notes.pdf` | — | `skipped` — plain file |

Statuses are final after Phase 1. Phase 2 does not change them.

`data1.cab` and `data1.hdr` together form an InstallShield cabinet set. The
InstallShield format is not compatible with Microsoft CAB even though both use
the `.cab` extension. extract-sbom identifies the pair by the `ISc(` magic bytes
at offset 0 and the `data*.cab` + `data*.hdr` naming pattern, then uses
`unshield` instead of `7zz`.

### 4.3 Phase 2: Who Scans What

This table shows only nodes that are scan targets: nodes with status `extracted`
or `syft-native`. Nodes with status `skipped` (such as `client.exe` and
`sign-plugin.ocx`) are not separate scan targets. They are, however, plain files
inside their parent's extraction directory, and Syft will encounter them when it
scans that directory.

**Extraction directories on disk.** Each extracted archive is unpacked into its
own dedicated temporary directory — for example,
`/tmp/extract-sbom-tar-abc123/` for `apache-tomcat-9.0.98.tar.gz`. Extracted
archives are not stored as subdirectories of each other. The logical nesting in
the delivery tree is maintained in memory by extract-sbom, not on disk. Syft
receives each extraction directory as an independent filesystem root.

The `/` appended to node names below signals that Syft scans a directory, not
the archive file itself.

**Extracted nodes — Syft scans each node's dedicated extraction directory:**

| Node | What the extraction directory contains | Typically found by Syft |
|---|---|---|
| `vendor-suite-3.2.zip/` | outer layer: RPMs, DEBs, `.tar.gz`, MSI, CABs, 7z — all as flat files | RPM and DEB packages directly; deeper archive contents come from their own scan targets below |
| `apache-tomcat-9.0.98.tar.gz/` | `lib/*.jar`, `webapps/vendor-app.ear` | Java packages from JAR manifests and POM properties; JARs and EAR are also `syft-native` nodes and packages attributed to them are moved there |
| `resources.tgz/` | `translations/*.properties` | nothing — no package manifests present |
| `client-setup.msi/` | extracted MSI payload including `client.exe` and `sign-plugin.ocx` inside `Program Files/` | PE `VERSIONINFO` from EXE and OCX if the supplier populated those fields; see §4.3.1 |
| `prereqs/vcredist.cab/` | extracted Microsoft CAB contents | PE `VERSIONINFO` from bundled binaries if present |
| `legacy-addon/data1.cab/` | extracted InstallShield contents | depends on what was bundled |
| `web/webapp-patch-1.2.1.7z/` | `webapp/` subtree with both `index.js` copies and `node_modules/minimist/` | `minimist@0.0.8` from `node_modules/minimist/package.json`; the bare `webapp/index.js` is not detected |

**Syft-native nodes — Syft scans the original file on disk:**

Each JAR, EAR, RPM, and DEB is first checked against the result of its parent
directory scan. If that scan already produced package locations pointing into
the file, extract-sbom reuses those packages and does not call Syft again. If
not, extract-sbom calls Syft directly on the original file.

### 4.3.1 MSI, EXE, and OCX: Three Nodes, Up To Three SBOM Components

`client-setup.msi` and the binaries it installs illustrate an important assembly
rule: container and contents can produce separate SBOM components.

`client.exe` and `sign-plugin.ocx` are `skipped` nodes in Phase 1 and are not
separate scan targets. They are, however, regular files inside the extracted MSI
payload directory, and Syft may catalog them as PE components when it scans that
directory.

The assembly phase can therefore produce up to three components:

- **`client-setup.msi`** — carries MSI product metadata (product name, version,
  manufacturer) read from the MSI Property table. This is the container identity.
- **`client.exe`** — carries PE `VERSIONINFO` data if the supplier populated
  those fields. This is the installed binary identity.
- **`sign-plugin.ocx`** — same as above.

`client.exe` and `sign-plugin.ocx` appear as separate CycloneDX components
linked as dependencies of `client-setup.msi` in the SBOM. There is no conflict
between MSI product metadata and PE `VERSIONINFO` fields: the MSI describes the
product as a whole; the PE binaries describe individual installed components.
The two sources are complementary.

### 4.4 The Two `index.js` Files: What Syft Can And Cannot See

`webapp-patch-1.2.1.7z` contains two copies of the same vulnerable library code:

```text
webapp/index.js                            (bare file copy, no package manifest)
webapp/node_modules/minimist/package.json  (declares name: minimist, version: 0.0.8)
webapp/node_modules/minimist/index.js      (actual library file inside npm package)
```

When Syft scans the extracted `webapp-patch-1.2.1.7z` directory, it finds
`node_modules/minimist/package.json` and records:

```
pkg:npm/minimist@0.0.8
```

This entry maps to CVE-2020-7598 (Prototype Pollution). A vulnerability scanner
working from the SBOM will flag it.

`webapp/index.js` contains the same vulnerable code, but there is no
`package.json` alongside it. Syft sees a JavaScript file and will not recognize it.
Accordingly, extract-sbom records the file as `skipped`. It will not appear in the
SBOM. A vulnerability scanner will not flag it.

This is not a bug in Syft or in extract-sbom. It is a fundamental property of
manifest-based package detection: **detection depends on the metadata the
supplier included, not on file content.** Section 6 discusses the full range of
implications.

## 5. Node Statuses

`internal/extract` assigns every status during Phase 1. The decision order for
each file is:

1. Depth limit exceeded → `skipped`
2. Syft-native format identified → `syft-native`
3. Not a recognized container → `skipped`
4. Extraction succeeded → `extracted`
5. Required helper tool absent → `tool-missing`
6. Hard safety rule tripped → `security-blocked`
7. Any other extraction failure → `failed`

| Status | Meaning | What happens in Phase 2 |
|---|---|---|
| `syft-native` | Syft handles this format natively. | Scanned by Syft — via parent directory reuse or direct scan. |
| `extracted` | Successfully unpacked. | Extracted directory is scanned by Syft. |
| `skipped` | Not pursued further. | Not a direct scan target. May still be covered by a parent directory scan. |
| `failed` | Extraction was attempted but did not finish. | Not a scan target. Subtree is marked incomplete in the report. |
| `security-blocked` | A hard safety rule stopped processing. | Not a scan target. Incident is documented in the report. |
| `tool-missing` | Required helper binary not installed. | Not a scan target. Node is visible in the report. For MSI files, product metadata is still recorded because it is read directly from the MSI Property table, independently of `7zz`. |

Only `extracted` and `syft-native` become scan targets.

### 5.1 What `skipped` Really Means

`skipped` does not mean "hidden". It means "recorded, but not its own scan
subject".

Two common cases:

1. A plain file such as `de.properties` is seen by syft inside an extracted directory.
   extract-sbom marks it `skipped` and does not keep it as a persistent child
   node, because the parent directory scan already covers it.
2. A tracked artifact hits an intentional stop condition such as a depth limit
   or an unsupported format. The node stays in the tree and the report records
   why processing stopped there.

## 6. Package Detection Reliability

Syft relies on package manifests and metadata files, not on file content
analysis. Detection quality therefore varies by format and by how thoroughly
the supplier packaged their components.

| Format / ecosystem | Detection mechanism | Reliability | False negative risk | False positive risk |
|---|---|---|---|---|
| RPM (`.rpm`) | RPM header metadata | Very high | Very low | Very low |
| DEB (`.deb`) | Debian package metadata | Very high | Very low | Very low |
| Alpine APK (`.apk`) | APK metadata | Very high | Very low | Very low |
| NuGet (`.nupkg`) | NuGet spec | High | Low | Low |
| Python wheel (`.whl`) | `.dist-info/METADATA` | High | Low | Low |
| Python egg (`.egg`) | `PKG-INFO` | Moderate | Moderate — older format, less consistently populated | Low |
| Ruby gem (`.gem`) | gemspec | High | Low | Low |
| Rust crate (`.crate`) | Cargo metadata | High | Low | Low |
| Java JAR / WAR / EAR | Maven `pom.properties`, `MANIFEST.MF` | High | Moderate — JARs without Maven metadata may have incomplete or missing version info | Low |
| npm / Node.js | `package.json` in `node_modules/` | High when manifest is present | **High when manifest is absent.** A vendored, bundled, or inline copy without its `package.json` is invisible. _The bare `webapp/index.js` in the running example is a direct instance of this._ | Low — a stale or mismatched `package.json` can produce a phantom entry |
| Go binaries | Build info embedded in the binary | Moderate | Moderate — stripped or non-standard builds lose embedded build info | Low |
| Windows PE (`.exe`, `.dll`, `.ocx`) | `VERSIONINFO` resource in the PE header | Low to moderate | **High.** Many production binaries lack `VERSIONINFO` or only carry a top-level product version, not library-level version. Whether `sign-plugin.ocx` in the running example is identifiable depends entirely on what the supplier compiled into it. | Moderate — `VERSIONINFO` is set by the build system and not independently verified |
| MSI product metadata | MSI Property table (`ProductName`, `ProductVersion`, `Manufacturer`) | High for the MSI as a product | **High for libraries bundled inside the MSI payload.** The Property table describes the product, not its transitive dependencies. | Low |
| Plain files with no manifest | Content heuristics only | Very low | **Very high.** No manifest, no identity. | Low |

**What this means for the SBOM consumer:**

A component listed in the SBOM was positively identified from package manifest
evidence found in the delivery.

A component absent from the SBOM only means no manifest evidence for it was
found. That is **not evidence of absence**. Stripped binaries, inline copies,
and bundled code without accompanying manifests are systematically undetectable
by this approach.

The most common sources of **false negatives** in practice:

- Bare source or compiled file copies bundled without their original package
  manifests — the `webapp/index.js` copy of minimist in the running example
- Statically compiled binaries that absorb third-party libraries without
  preserving library-level metadata
- Windows PE payloads where the supplier did not populate `VERSIONINFO`

The most common sources of **false positives** in practice:

- Stale `package.json` entries remaining after a dependency was removed
- `VERSIONINFO` reporting the overall product version instead of the embedded
  component version
- Overly broad Syft heuristics matching a file that does not actually represent
  a versioned package

## 7. How The Scan Phase Works In Detail

### 7.1 Extracted Directories Are Scanned First

All `extracted` nodes are scanned in parallel. Each produces:

- a CycloneDX BOM for that subtree
- Syft's internal package list including the locations where each package's
  evidence was found

The package locations enable the next step.

### 7.2 Package Attribution To Syft-Native Child Nodes

**Package attribution** is the process of assigning each Syft-discovered package
to the most specific node in the delivery tree that directly contains it.

The need arises because one directory scan covers nested content. When Syft
scans the extraction directory of `apache-tomcat-9.0.98.tar.gz`, it reads the
entire tree — including the content of `catalina.jar`, `tomcat-embed-core.jar`,
and `vendor-app.ear`. All packages found anywhere in that tree initially belong
to the TAR node. Attribution then reassigns each package to the specific child
node that actually contains it.

Syft records **location paths** for every package it finds: the exact filesystem
path to the file where the manifest or metadata was found. For a Maven package
inside a JAR, that path looks like:

```text
/tmp/extract-sbom-tar-1234/lib/catalina.jar!/META-INF/maven/org.apache.tomcat/tomcat-catalina/pom.properties
```

The `!/` separator is a Syft convention: the portion before it is a real path on
disk; the portion after is a path inside an archive. extract-sbom takes the real
disk path (everything up to the `!`) and checks whether it matches the on-disk
path of any `syft-native` descendant node.

**One match — the normal case.** The location's disk prefix
`/tmp/extract-sbom-tar-1234/lib/catalina.jar` matches the on-disk path of the
`lib/catalina.jar` node. The package is attributed to `lib/catalina.jar`. In the
SBOM it appears under that node, not under `apache-tomcat-9.0.98.tar.gz`.

**Several matches.** This can happen when archive formats are nested and
multiple ancestor nodes are `syft-native`. For example, if `vendor-app.ear`
contains `WEB-INF/lib/inner.jar`, and that JAR is also tracked as a `syft-native`
node, then a package inside `inner.jar` would match both the EAR path and the
JAR path. The longer (more specific) path wins: the path ending at `inner.jar`
is longer than the path ending at `vendor-app.ear`, so the package goes to
`inner.jar`.

This is not arbitrary. A longer matching prefix identifies the innermost file
that directly holds the evidence. Attributing to the EAR would be a coarser
claim — the evidence was found somewhere inside the EAR — when a more precise
claim is available: the evidence was found inside this specific JAR inside the
EAR.

**No match.** Some packages have evidence paths that do not point inside any
`syft-native` child node. A configuration file or script placed directly at the
TAR root, such as `/tmp/extract-sbom-tar-1234/conf/server.xml`, would not match
any child node path. The package stays attributed to the `apache-tomcat-9.0.98.tar.gz`
node itself. This is also the correct attribution: there is no more specific
node that contains it.

### 7.3 Direct File Scans Are The Fallback

After attribution, every `syft-native` node is in one of two states:

- **Covered.** One or more packages were attributed to this node from the
  parent directory scan. extract-sbom uses those packages directly. No second
  Syft invocation is made.
- **Not covered.** No packages were attributed. extract-sbom calls Syft
  directly on the original file.

**Why is reuse valid?** When Syft scans the extraction directory of
`apache-tomcat-9.0.98.tar.gz`, it opens and reads `lib/catalina.jar` as part of
that scan. The resulting packages — with their location evidence — are exactly
what a separate direct scan of `catalina.jar` would also produce. The file was
already read; applying those results to the node is not a shortcut, it is using
the same data from a scan that already happened.

**When does a node end up not covered?** In practice this is rare for nodes
that are direct children of an extracted archive, because the parent scan reads
them. It can occur if Syft's directory scan could not penetrate a particular
archive format that Syft can handle as a standalone file but not when encountered
nested inside another archive. Direct scan is the safe fallback for all such
cases.

## 8. How The Final SBOM Is Built

After scanning, `internal/assembly` walks the delivery tree depth-first and
builds one CycloneDX BOM. Siblings are sorted before recursing; the walk order
is therefore deterministic and independent of scan completion order.

For every tracked node (every `extracted`, `syft-native`, `failed`,
`security-blocked`, or `tool-missing` node that was persisted in the tree),
assembly creates one CycloneDX **component** and attaches:

- `extract-sbom:delivery-path` — the stable logical path inside the delivery
- `extract-sbom:status` — the extraction status from Phase 1
- The packages attributed to this node from Phase 2, each as a separate
  CycloneDX component linked via a dependency relationship and with a BOMRef
  namespaced under the owning node
- For MSI nodes: `ProductName`, `ProductVersion`, and `Manufacturer` from the
  MSI Property table are mapped to the standard CycloneDX component fields
  `Name`, `Version`, and `Supplier`. `ProductCode`, `UpgradeCode`, and
  `Language` become custom `extract-sbom:msi-*` properties.

`skipped` leaf nodes such as plain files and PDFs are not persisted in the
extraction tree. They are neither SBOM components nor audit-report entries.
Their presence on disk is still covered by the parent directory scan — Syft
encounters them when it scans the extraction directory.

Here is what each node from the running example contributes:

**`vendor-suite-3.2.zip`** — one top-level component. The ZIP extraction
directory holds the delivery's outermost files; any packages found directly
there (none in this example) would stay with this component. All child
components are nested below it in the SBOM.

**`linux/server-3.2.rpm`** — one component. Syft reads the RPM header and
records the package declared there: name, version, epoch, architecture.

**`linux/libssl1.1_1.1.1n-0_amd64.deb`** — one component. Syft reads the
Debian `control` file and records `libssl1.1 1.1.1n`.

**`linux/apache-tomcat-9.0.98.tar.gz`** — one component. Packages found
directly at the TAR root (not inside a nested archive) stay here. The four JAR
and EAR nodes are dependent components linked via CycloneDX dependencies.

**`lib/catalina.jar`**, **`lib/tomcat-embed-core-9.0.98.jar`**,
**`lib/servlet-api.jar`** — one component each. Their packages were attributed
from the TAR scan via §7.2 (location prefix match on the JAR path); no
additional Syft invocation. Evidence paths point into the respective JAR files.

**`webapps/vendor-app.ear`** — one component. Packages found inside the EAR
(including any embedded WARs or JARs that Syft traverses) are attributed here
if no more specific child node matches.

**`linux/resources.tgz`** — one component. The scan found only `.properties`
files; Syft recognized no package manifests. No packages attached.

**`windows/client-setup.msi`** — one component. Assembly maps `ProductName`,
`ProductVersion`, and `Manufacturer` from the MSI Property table to the standard
CycloneDX fields `Name`, `Version`, and `Supplier`. `ProductCode`, `UpgradeCode`,
and `Language` become custom `extract-sbom:msi-*` properties. If Syft found PE
`VERSIONINFO` data for `client.exe` and `sign-plugin.ocx` while scanning the
extracted MSI payload directory, those appear as dependent components linked to
this node. If the supplier did not populate `VERSIONINFO`, nothing is attached
for those binaries.

**`windows/prereqs/vcredist.cab`** — one component. Any PE binaries inside
with populated `VERSIONINFO` become packages here.

**`windows/legacy-addon/data1.cab`** — one component. Contents depend on
what the InstallShield package bundles.

**`web/webapp-patch-1.2.1.7z`** — one component. The scan found
`pkg:npm/minimist@0.0.8` from `webapp/node_modules/minimist/package.json`.
This package is attached here with that `package.json` as evidence path. The
bare `webapp/index.js` was not identified and generates no package record.

**`docs/release-notes.pdf`** — `skipped` leaf; not persisted in the tree, not
an SBOM component. Syft still encounters the file when scanning the parent
extraction directory, but finds no package manifest.

---

After all components are built, assembly sorts packages, properties, and
dependencies into a canonical order, then writes the single CycloneDX BOM and
the parallel audit report.

## 9. Why The Result Is Deterministic

For the same input file and the same effective configuration, extract-sbom
applies the same decision rules and emits the same logical structure.

- Format identification follows fixed rules.
- Status assignment follows fixed rules.
- Scan targets come from those statuses.
- Package attribution uses explicit path-prefix matching, not fuzzy heuristics.
- The most specific matching path wins when several candidates exist.
- Package collections are sorted before reuse.
- Final components, properties, and dependencies are sorted during assembly.
- Delivery-path-based BOM references come from stable node paths.

Parallel scan workers do not break determinism. They change when a scan
finishes, but not which node owns which result or how the final document is
ordered.

Determinism has a boundary: if the input file or the effective configuration
changes, the output can change.

## 10. Why The Result Is Trustworthy

- Syft-native formats stay intact so Syft can use the stronger cataloger.
- MSI metadata comes from the MSI Property table, not from guessed filenames.
- Package reuse requires concrete Syft location evidence.
- Direct file scans remain the fallback when that evidence is missing.
- Hard safety rules stay separate from scan optimizations.
- Missing tools, failed subtrees, and blocked subtrees stay visible.
- Detection limitations are documented in section 6, not hidden.

That combination makes the output defensible: an operator can explain why a
package appears, why a subtree is incomplete, and which evidence path supports
a finding.

## 11. What The Tool Does Not Claim

extract-sbom produces an auditable SBOM and an audit report. It does not claim
to do any of the following:

- detect packages from file content without a machine-readable manifest
- malware analysis
- behavioral analysis
- exploitability assessment
- vulnerability matching by itself

Its job is to make one supplier delivery transparent enough that downstream
vulnerability and compliance tooling can work on a defensible basis.

## 12. Where To Read Next

- [README.md](README.md) for the product overview
- [USAGE.md](USAGE.md) for operator-facing CLI behavior and output handling
- [DESIGN.md](DESIGN.md) for formal requirements and security intent
- [MODULE_GUIDE.md](MODULE_GUIDE.md) for the implementation-level module design