using System.Text.Json;
using System.Text.Json.Serialization;

namespace Rudy.Chain;

public sealed class InputException(string message) : Exception(message);

public sealed record Component(string Ref, string Type, string Group, string Name, string Version,
    string Purl, string Scope, string[] Licenses, SortedDictionary<string, string> Hashes)
{
    public string PackageKey => JsonSerializer.Serialize(new[] { Type, Group, Name });
    public PackageVariant Snapshot => new(Type, Group, Name, Version, Purl, Scope, Licenses, Hashes);
    public PackageCoordinate Coordinate => new(Type, Group, Name, Version, Purl);
    public string Variant => JsonSerializer.Serialize(Snapshot);
    public string EdgeKey => JsonSerializer.Serialize(Coordinate);
    public bool HasStrongHash => Hashes.Keys.Any(k => k is "SHA-256" or "SHA-384" or "SHA-512");
}

public sealed record Inventory(string Digest, string SpecVersion, string Root,
    SortedDictionary<string, Component> Components, SortedDictionary<string, string[]> Dependencies,
    string[] Notices);

public sealed record Finding(string RuleId, string Level, string ComponentRef, string Message,
    string[] Path, bool PathTruncated);
public sealed record AuditReport(string Schema, string ToolVersion, string InputSha256, string Root,
    int Components, int Edges, int Reachable, int UnknownDependencyRecords,
    string[][] Cycles, string[] Notices, Finding[] Findings);
public sealed record PackageIdentity(string Type, string Group, string Name);
public sealed record PackageCoordinate(string Type, string Group, string Name, string Version, string Purl);
public sealed record PackageVariant(string Type, string Group, string Name, string Version, string Purl,
    string Scope, string[] Licenses, SortedDictionary<string, string> Hashes);
public sealed record DependencyEdge(PackageCoordinate From, PackageCoordinate To);
public sealed record PackageChange(PackageIdentity Package, PackageVariant[] Before, PackageVariant[] After);
public sealed record DiffReport(string Schema, string BeforeSha256, string AfterSha256,
    PackageCoordinate BeforeRoot, PackageCoordinate AfterRoot,
    PackageChange[] Added, PackageChange[] Removed, PackageChange[] Changed,
    DependencyEdge[] AddedEdges, DependencyEdge[] RemovedEdges, PackageCoordinate[] BeforeUnknown, PackageCoordinate[] AfterUnknown,
    string[] Notices);

public static class JsonOutput
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never
    };
    public static string Serialize(object value) => JsonSerializer.Serialize(value, Options);
}
