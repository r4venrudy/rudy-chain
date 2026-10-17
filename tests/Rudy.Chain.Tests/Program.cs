using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Rudy.Chain;

var root = Path.GetFullPath(args.Length == 0 ? "." : args[0]);
var tests = new List<(string Name, Action Body)>();
void Test(string name, Action body) => tests.Add((name, body));
void Assert(bool condition, string message = "Assertion failed") { if (!condition) throw new Exception(message); }
void Reject(Action body)
{
    try { body(); } catch (InputException) { return; }
    throw new Exception("Expected rejected input");
}
JsonObject Fixture(int size = 5)
{
    var components = new JsonArray();
    for (var i = 1; i < size; i++) components.Add(Component(i));
    return new JsonObject
    {
        ["bomFormat"] = "CycloneDX",
        ["specVersion"] = "1.6",
        ["version"] = 1,
        ["metadata"] = new JsonObject { ["component"] = Component(0) },
        ["components"] = components,
        ["dependencies"] = new JsonArray(Enumerable.Range(0, size).Select(i => (JsonNode?)new JsonObject
        { ["ref"] = $"c{i}", ["dependsOn"] = new JsonArray() }).ToArray())
    };
}
JsonObject Component(int i) => new()
{
    ["type"] = i == 0 ? "application" : "library",
    ["name"] = $"package-{i}",
    ["bom-ref"] = $"c{i}",
    ["version"] = "1.0.0",
    ["purl"] = $"pkg:generic/package-{i}@1.0.0",
    ["hashes"] = new JsonArray(new JsonObject { ["alg"] = "SHA-256", ["content"] = new string('a', 64) })
};
Inventory Parse(JsonNode value) => Import.Parse(value.ToJsonString());
JsonObject Item(JsonNode value, int i) => (JsonObject)(i == 0 ? value["metadata"]!["component"]! : value["components"]![i - 1]!);
void Edge(JsonNode value, int from, params int[] to) => value["dependencies"]![from]!["dependsOn"] =
    new JsonArray(to.Select(i => (JsonNode?)JsonValue.Create($"c{i}")).ToArray());

Test("empty explicit leaves have no findings", () =>
{
    var f = Fixture(1); var report = Analysis.Audit(Parse(f));
    Assert(report.Findings.Length == 0 && report.UnknownDependencyRecords == 0);
});
Test("shortest deterministic root path through a diamond", () =>
{
    var f = Fixture(); Edge(f, 0, 2, 1); Edge(f, 1, 3); Edge(f, 2, 3); Edge(f, 3, 4);
    var graph = new Graph(Parse(f));
    Assert(Graph.Path(graph.Traverse("c0"), "c4").Path.SequenceEqual(new[] { "c0", "c1", "c3", "c4" }));
});
Test("reverse impact contains exact ancestors", () =>
{
    var f = Fixture(); Edge(f, 0, 1); Edge(f, 1, 2); Edge(f, 3, 2);
    Assert(new Graph(Parse(f)).Traverse("c2", true).Keys.Order().SequenceEqual(new[] { "c0", "c1", "c2", "c3" }));
});
Test("omitted records are unknown", () =>
{
    var f = Fixture(2); Edge(f, 0, 1); f["dependencies"]!.AsArray().RemoveAt(1);
    var r = Analysis.Audit(Parse(f)); Assert(r.UnknownDependencyRecords == 1 && r.Findings.Any(x => x.RuleId == "CHAIN004"));
});
Test("unreachable node is a declaration observation", () =>
{
    var r = Analysis.Audit(Parse(Fixture(2))); Assert(r.Reachable == 1 && r.Findings.Single().RuleId == "CHAIN005");
});
Test("cycles include self loops and multi-node SCCs", () =>
{
    var f = Fixture(); Edge(f, 0, 0); Edge(f, 1, 2); Edge(f, 2, 1); Edge(f, 3, 4);
    var cycles = new Graph(Parse(f)).Cycles();
    Assert(cycles.Length == 2 && cycles[0].SequenceEqual(new[] { "c0" }) && cycles[1].SequenceEqual(new[] { "c1", "c2" }));
});
Test("strong digest missing and malformed are distinct", () =>
{
    var f = Fixture(1); Item(f, 0)["hashes"] = new JsonArray(new JsonObject { ["alg"] = "MD5", ["content"] = new string('a', 32) });
    Assert(Analysis.Audit(Parse(f)).Findings.Single().RuleId == "CHAIN001");
    Item(f, 0)["hashes"]![0]!["alg"] = "SHA-256"; Reject(() => Parse(f));
});
Test("same purl and algorithm conflicting bytes flag both declarations", () =>
{
    var f = Fixture(2); Edge(f, 0, 1); Item(f, 1)["purl"] = Item(f, 0)["purl"]!.GetValue<string>();
    Item(f, 1)["hashes"]![0]!["content"] = new string('b', 64);
    Assert(Analysis.Audit(Parse(f)).Findings.Count(x => x.RuleId == "CHAIN008") == 2);
});
Test("different algorithms are not a digest conflict", () =>
{
    var f = Fixture(2); Edge(f, 0, 1); Item(f, 1)["purl"] = Item(f, 0)["purl"]!.GetValue<string>();
    Item(f, 1)["hashes"]![0]!["alg"] = "SHA-512"; Item(f, 1)["hashes"]![0]!["content"] = new string('b', 128);
    Assert(!Analysis.Audit(Parse(f)).Findings.Any(x => x.RuleId == "CHAIN008"));
});
Test("policy denies exact purl and whole license value", () =>
{
    var f = Fixture(1); Item(f, 0)["licenses"] = new JsonArray(new JsonObject { ["expression"] = "MIT OR GPL-3.0-only" });
    var bom = Parse(f); var p = Policy.Default with { DeniedPurls = [bom.Components["c0"].Purl], DeniedLicenseValues = ["MIT OR GPL-3.0-only"] };
    Assert(Analysis.Audit(bom, p).Findings.Count(x => x.Level == "error") == 2);
    Assert(!Analysis.Audit(bom, p with { DeniedPurls = [], DeniedLicenseValues = ["GPL-3.0-only"] }).Findings.Any(x => x.RuleId == "CHAIN009"));
});
Test("audit dependency path truncation is explicit", () =>
{
    var f = Fixture(50); for (var i = 0; i < 49; i++) Edge(f, i, i + 1);
    Item(f, 49).Remove("version"); var finding = Analysis.Audit(Parse(f)).Findings.Single();
    Assert(finding.Path.Length == 32 && finding.PathTruncated && finding.Path[^1] == "c49");
});
Test("renumbering all bom refs creates no semantic diff", () =>
{
    var f = Fixture(2); Edge(f, 0, 1); var original = Parse(f);
    var renamed = Import.Parse(f.ToJsonString().Replace("c0", "other-root").Replace("c1", "other-library"));
    var diff = Analysis.Diff(original, renamed);
    Assert(diff.Added.Length + diff.Removed.Length + diff.Changed.Length + diff.AddedEdges.Length + diff.RemovedEdges.Length == 0);
});
Test("diff preserves multiple installed variants", () =>
{
    var f = Fixture(3); Item(f, 2)["name"] = "package-1";
    var before = Parse(f); Item(f, 2)["version"] = "2.0.0";
    var diff = Analysis.Diff(before, Parse(f)); Assert(diff.Changed.Single().Before.Length == 2 && diff.Changed.Single().After.Length == 2);
});
Test("diff exposes edge-only changes and unknown record changes", () =>
{
    var f = Fixture(2); var before = Parse(f); Edge(f, 0, 1); f["dependencies"]!.AsArray().RemoveAt(1);
    var diff = Analysis.Diff(before, Parse(f)); Assert(diff.Changed.Length == 0 && diff.AddedEdges.Length == 1 && diff.AfterUnknown.Length == 1);
});
Test("nested containment does not imply dependency", () =>
{
    var f = Fixture(2); Item(f, 0)["components"] = f["components"]!.DeepClone(); f["components"] = new JsonArray();
    Assert(Analysis.Audit(Parse(f)).Reachable == 1);
});
Test("SARIF retains policy findings and fingerprints", () =>
{
    var report = Analysis.Audit(Parse(Fixture(2))); var result = Sarif.Export(report);
    Assert(result["version"]!.GetValue<string>() == "2.1.0");
    Assert(result["runs"]![0]!["results"]!.AsArray().Count == report.Findings.Length);
    Assert(result["runs"]![0]!["results"]![0]!["partialFingerprints"]!["rudyChain/v1"]!.GetValue<string>().Length == 64);
});
Test("array ordering does not affect semantic comparison", () =>
{
    var f = Fixture(4); Edge(f, 0, 1, 2, 3); var before = Parse(f);
    var c = f["components"]!.AsArray().Select(x => x!.DeepClone()).Reverse().ToArray(); f["components"] = new JsonArray(c);
    var diff = Analysis.Diff(before, Parse(f)); Assert(diff.Changed.Length == 0 && diff.AddedEdges.Length == 0);
});
Test("UTF-8 BOM accepted", () =>
{
    var bytes = Encoding.UTF8.GetBytes(Fixture(1).ToJsonString()); Assert(Import.Parse(new byte[] { 239, 187, 191 }.Concat(bytes).ToArray()).Components.Count == 1);
});

var mutations = new (string Name, Action<JsonObject> Change)[] {
    ("wrong format", f => f["bomFormat"] = "SPDX"),
    ("unsupported version", f => f["specVersion"] = "99.0"),
    ("missing metadata", f => f.Remove("metadata")),
    ("missing root", f => f["metadata"]!.AsObject().Remove("component")),
    ("non-object component", f => f["components"]![0] = 3),
    ("duplicate bom-ref", f => Item(f, 1)["bom-ref"] = "c0"),
    ("missing bom-ref", f => Item(f, 1).Remove("bom-ref")),
    ("empty name", f => Item(f, 1)["name"] = " "),
    ("null version", f => Item(f, 1)["version"] = null),
    ("unknown dependency source", f => f["dependencies"]![0]!["ref"] = "absent"),
    ("unknown dependency target", f => f["dependencies"]![0]!["dependsOn"] = new JsonArray("absent")),
    ("duplicate dependency edge", f => Edge(f, 0, 1, 1)),
    ("duplicate dependency record", f => f["dependencies"]!.AsArray().Add(f["dependencies"]![0]!.DeepClone())),
    ("service graph", f => f["services"] = new JsonArray(new JsonObject())),
    ("provides graph", f => f["dependencies"]![0]!["provides"] = new JsonArray("c1")),
    ("invalid strong digest", f => Item(f, 0)["hashes"]![0]!["content"] = new string('z', 64)),
    ("duplicate hash algorithm", f => Item(f, 0)["hashes"]!.AsArray().Add(Item(f, 0)["hashes"]![0]!.DeepClone())),
    ("unsupported license choice", f => Item(f, 0)["licenses"] = new JsonArray(new JsonObject())),
    ("oversized string", f => Item(f, 0)["name"] = new string('a', 8193))
};
foreach (var mutation in mutations) Test("reject " + mutation.Name, () => { var f = Fixture(); mutation.Change(f); Reject(() => Parse(f)); });
Test("reject duplicate JSON properties", () => Reject(() => Import.Parse("{\"bomFormat\":\"CycloneDX\",\"bomFormat\":\"CycloneDX\"}")));
Test("reject malformed JSON", () => Reject(() => Import.Parse("{broken}")));
Test("reject invalid UTF-8", () => Reject(() => Import.Parse(new byte[] { 123, 34, 120, 34, 58, 34, 0xff, 34, 125 })));
Test("reject ambiguous license choices", () =>
{
    var f = Fixture(1); Item(f, 0)["licenses"] = new JsonArray(new JsonObject { ["expression"] = "MIT", ["license"] = new JsonObject { ["id"] = "Apache-2.0" } });
    Reject(() => Parse(f));
});
Test("reject depth overflow", () => Reject(() => Import.Parse(new string('[', 65) + "0" + new string(']', 65))));
Test("reject byte overflow", () => Reject(() => Import.Parse(new byte[Import.MaxBytes + 1])));
Test("reject component overflow", () => Reject(() => Parse(Fixture(Import.MaxComponents + 1))));
Test("reject edge overflow", () =>
{
    var f = Fixture(1001); for (var i = 0; i < 100; i++) Edge(f, i, Enumerable.Range(0, 1001).ToArray());
    Reject(() => Parse(f));
});
Test("reject node overflow in ignored fields", () =>
{
    var f = Fixture(1); f["ignored"] = new JsonArray(Enumerable.Range(0, 500_001).Select(_ => (JsonNode?)JsonValue.Create(0)).ToArray());
    Reject(() => Parse(f));
});

Test("random graphs agree with independent transitive closure oracle", () =>
{
    var random = new Random(7351);
    for (var sample = 0; sample < 100; sample++)
    {
        const int n = 12; var f = Fixture(n); var closure = new bool[n, n];
        for (var a = 0; a < n; a++)
        {
            var edges = new List<int>(); for (var b = 0; b < n; b++)
                if (random.NextDouble() < .12) { edges.Add(b); closure[a, b] = true; }
            Edge(f, a, edges.ToArray());
        }
        var selfLoops = Enumerable.Range(0, n).Where(i => closure[i, i]).ToHashSet();
        for (var i = 0; i < n; i++) closure[i, i] = true;
        for (var k = 0; k < n; k++) for (var i = 0; i < n; i++) for (var j = 0; j < n; j++) closure[i, j] |= closure[i, k] && closure[k, j];
        var graph = new Graph(Parse(f)); var cycles = graph.Cycles();
        for (var i = 0; i < n; i++)
        {
            var reached = graph.Traverse($"c{i}"); var reverse = graph.Traverse($"c{i}", true);
            for (var j = 0; j < n; j++) { Assert(reached.ContainsKey($"c{j}") == closure[i, j]); Assert(reverse.ContainsKey($"c{j}") == closure[j, i]); }
            var expected = Enumerable.Range(0, n).Where(j => closure[i, j] && closure[j, i]).Select(j => $"c{j}").Order(StringComparer.Ordinal).ToArray();
            var actual = cycles.FirstOrDefault(g => g.Contains($"c{i}"));
            Assert(expected.Length > 1 || selfLoops.Contains(i) ? actual is not null && actual.SequenceEqual(expected) : actual is null);
        }
    }
});
Test("10,000-node chain uses iterative traversal", () =>
{
    var f = Fixture(Import.MaxComponents); for (var i = 0; i < Import.MaxComponents - 1; i++) Edge(f, i, i + 1);
    var graph = new Graph(Parse(f)); Assert(graph.Traverse("c0").Count == Import.MaxComponents && graph.Cycles().Length == 0);
});

(int Code, string Out, string Err) Cli(params string[] arguments)
{
    var info = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet")
    { RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = root };
    info.ArgumentList.Add(Path.Combine(root, "src/Rudy.Chain.Cli/bin/Release/net10.0/Rudy.Chain.Cli.dll"));
    foreach (var arg in arguments) info.ArgumentList.Add(arg);
    using var process = Process.Start(info)!;
    var output = process.StandardOutput.ReadToEndAsync(); var error = process.StandardError.ReadToEndAsync();
    if (!process.WaitForExit(20_000)) { process.Kill(true); throw new Exception("CLI timed out"); }
    return (process.ExitCode, output.GetAwaiter().GetResult(), error.GetAwaiter().GetResult());
}
Test("CLI audit JSON and default gate", () =>
{
    var result = Cli("audit", "examples/before.cdx.json"); Assert(result.Code == 0 && result.Err.Length == 0);
    using var doc = JsonDocument.Parse(result.Out); Assert(doc.RootElement.GetProperty("schema").GetString() == "rudy-chain/audit/v1");
});
Test("CLI policy error exit retains JSON report", () =>
{
    var result = Cli("audit", "examples/after.cdx.json", "--policy", "examples/policy.json"); Assert(result.Code == 1);
    using var doc = JsonDocument.Parse(result.Out); Assert(doc.RootElement.GetProperty("findings").EnumerateArray().Any(f => f.GetProperty("ruleId").GetString() == "CHAIN007"));
});
Test("CLI SARIF and warning gate", () =>
{
    var result = Cli("audit", "examples/after.cdx.json", "--format", "sarif", "--fail-on", "warning");
    Assert(result.Code == 1); using var doc = JsonDocument.Parse(result.Out); Assert(doc.RootElement.GetProperty("version").GetString() == "2.1.0");
});
Test("CLI why and impact", () =>
{
    var why = Cli("why", "examples/before.cdx.json", "parser"); Assert(why.Code == 0);
    using var doc = JsonDocument.Parse(why.Out); Assert(doc.RootElement.GetProperty("path").GetArrayLength() == 3);
    var impact = Cli("impact", "examples/before.cdx.json", "parser"); Assert(impact.Code == 0);
    using var impactDoc = JsonDocument.Parse(impact.Out); Assert(impactDoc.RootElement.GetProperty("dependents").GetArrayLength() == 2);
});
Test("CLI diff", () =>
{
    var result = Cli("diff", "examples/before.cdx.json", "examples/after.cdx.json");
    Assert(result.Code == 0); using var doc = JsonDocument.Parse(result.Out); Assert(doc.RootElement.GetProperty("changed").GetArrayLength() == 1);
});
Test("CLI usage and missing files have no stdout", () =>
{
    foreach (var arguments in new[] { new[] { "audit", "no-such-file" }, new[] { "why", "examples/before.cdx.json", "absent" },
        new[] { "audit", "examples/before.cdx.json", "--formatt", "sarif" }, new[] { "audit", "examples/before.cdx.json", "--format", "xml" } })
    { var r = Cli(arguments); Assert(r.Code == 2 && r.Out.Length == 0 && r.Err.Length > 0); }
});
Test("CLI duplicate options rejected", () => Assert(Cli("audit", "examples/before.cdx.json", "--format", "json", "--format", "sarif").Code == 2));
Test("strict policy typos rejected", () =>
{
    var path = Path.GetTempFileName(); try { File.WriteAllText(path, "{\"requireHash\":true}"); Reject(() => Policy.Load(path)); } finally { File.Delete(path); }
});
Test("strict policy nonboolean flags rejected", () =>
{
    var path = Path.GetTempFileName(); try { File.WriteAllText(path, "{\"requireStrongHash\":\"true\"}"); Reject(() => Policy.Load(path)); } finally { File.Delete(path); }
});

Test("missing purl participates in the warning gate", () =>
{
    var f = Fixture(1); Item(f, 0).Remove("purl");
    Assert(Analysis.Audit(Parse(f)).Findings.Single().Level == "warning");
    var file = Path.GetTempFileName();
    try { File.WriteAllText(file, f.ToJsonString()); Assert(Cli("audit", file, "--fail-on", "warning").Code == 1); }
    finally { File.Delete(file); }
});
Test("optional license requirement loads strictly and produces SARIF warnings", () =>
{
    var file = Path.GetTempFileName();
    try
    {
        File.WriteAllText(file, "{\"requireLicense\":true}");
        var p = Policy.Load(file); var f = Fixture(1);
        var report = Analysis.Audit(Parse(f), p);
        Assert(report.Findings.Single().RuleId == "CHAIN010");
        var inventoryFile = Path.GetTempFileName();
        try { File.WriteAllText(inventoryFile,f.ToJsonString()); Assert(Cli("audit", inventoryFile, "--policy", file, "--fail-on", "warning").Code == 1); }
        finally { File.Delete(inventoryFile); }
        Assert(Sarif.Export(report)["runs"]![0]!["tool"]!["driver"]!["rules"]!.AsArray().Any(rule => rule!["id"]!.GetValue<string>() == "CHAIN010"));
        Item(f,0)["licenses"] = new JsonArray(new JsonObject { ["license"] = new JsonObject { ["id"] = "MIT" } });
        Assert(Analysis.Audit(Parse(f),p).Findings.Length == 0);
        File.WriteAllText(file,"{\"requireLicense\":null}"); Reject(() => Policy.Load(file));
    }
    finally { File.Delete(file); }
});

Test("component type deny list is exact and opt-in", () =>
{
    var file = Path.GetTempFileName();
    try
    {
        File.WriteAllText(file,"{\"deniedComponentTypes\":[\"application\"]}");
        var report = Analysis.Audit(Parse(Fixture(1)),Policy.Load(file));
        Assert(report.Findings.Single().RuleId == "CHAIN011" && report.Findings.Single().Level == "error");
        Assert(Sarif.Export(report)["runs"]![0]!["tool"]!["driver"]!["rules"]!.AsArray().Any(rule => rule!["id"]!.GetValue<string>() == "CHAIN011"));
        File.WriteAllText(file,"{\"deniedComponentTypes\":[\"Application\"]}");
        Assert(Analysis.Audit(Parse(Fixture(1)),Policy.Load(file)).Findings.Length == 0);
        File.WriteAllText(file,"{\"deniedComponentTypes\":[42]}"); Reject(() => Policy.Load(file));
    }
    finally { File.Delete(file); }
});
Test("CLI summary distinguishes reachable nodes, leaves and unknown records", () =>
{
    var result = Cli("summary","examples/after.cdx.json"); Assert(result.Code == 0);
    using var doc = JsonDocument.Parse(result.Out); var data = doc.RootElement;
    Assert(data.GetProperty("schema").GetString() == "rudy-chain/summary/v1");
    Assert(data.GetProperty("components").GetInt32() == 4);
    Assert(data.GetProperty("unknownDependencyRecords").GetInt32() == 1);
    Assert(data.GetProperty("declaredLeaves").GetInt32() == 1);
    Assert(data.GetProperty("types").GetProperty("application").GetInt32() == 1);
    Assert(Cli("summary","examples/after.cdx.json","--unknown").Code == 2);
});
var failures = 0;
foreach (var test in tests)
{
    try { test.Body(); Console.WriteLine("PASS " + test.Name); }
    catch (Exception ex) { failures++; Console.Error.WriteLine("FAIL " + test.Name + ": " + ex.Message); }
}
Console.WriteLine($"{tests.Count - failures}/{tests.Count} tests passed.");
return failures == 0 ? 0 : 1;
