using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace Rudy.Chain;

public static class Sarif
{
    public static readonly SortedDictionary<string, string> Rules = new(StringComparer.Ordinal)
    {
        ["CHAIN001"] = "Missing strong digest", ["CHAIN002"] = "Missing version",
        ["CHAIN003"] = "Missing package URL", ["CHAIN004"] = "Unknown dependency record",
        ["CHAIN005"] = "No declared root path", ["CHAIN006"] = "Dependency cycle",
        ["CHAIN007"] = "Denied package URL", ["CHAIN008"] = "Conflicting package digests",
        ["CHAIN009"] = "Denied complete license value",
        ["CHAIN010"] = "Missing license declaration",
        ["CHAIN011"] = "Denied component type"
    };
    public static JsonObject Export(AuditReport report)
    {
        var rules = new JsonArray();
        foreach (var (id, name) in Rules) rules.Add(new JsonObject { ["id"] = id, ["shortDescription"] = new JsonObject { ["text"] = name } });
        var results = new JsonArray();
        foreach (var f in report.Findings)
        {
            var stable = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(
                System.Text.Json.JsonSerializer.Serialize(new[] { f.RuleId, f.ComponentRef }))));
            results.Add(new JsonObject
            {
                ["ruleId"] = f.RuleId, ["level"] = f.Level,
                ["message"] = new JsonObject { ["text"] = f.Message },
                ["partialFingerprints"] = new JsonObject { ["rudyChain/v1"] = stable },
                ["properties"] = new JsonObject
                {
                    ["componentRef"] = f.ComponentRef, ["inputSha256"] = report.InputSha256,
                    ["dependencyPath"] = new JsonArray(f.Path.Select(p => (JsonNode?)JsonValue.Create(p)).ToArray()),
                    ["pathTruncated"] = f.PathTruncated
                }
            });
        }
        return new JsonObject
        {
            ["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json", ["version"] = "2.1.0",
            ["runs"] = new JsonArray(new JsonObject
            {
                ["tool"] = new JsonObject { ["driver"] = new JsonObject { ["name"] = "Rudy Chain", ["version"] = "0.1.0", ["informationUri"] = "https://github.com/r4venrudy/rudy-chain", ["rules"] = rules } },
                ["results"] = results,
                ["properties"] = new JsonObject { ["inputSha256"] = report.InputSha256, ["coverageNotices"] = new JsonArray(report.Notices.Select(n => (JsonNode?)JsonValue.Create(n)).ToArray()) }
            })
        };
    }
}
