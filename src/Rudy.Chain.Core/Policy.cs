namespace Rudy.Chain;

public sealed record Policy(bool RequireStrongHash, bool RequireVersion, bool RequirePurl,
    bool RequireKnownDependencies, string[] DeniedPurls, string[] DeniedLicenseValues)
{
    public bool RequireLicense { get; init; }
    public static Policy Default { get; } = new(true, true, true, true, [], []);
    public static Policy Load(string path)
    {
        using var doc = Import.ReadJson(Import.ReadBounded(path, 64 * 1024), 64 * 1024);
        var root = doc.RootElement;
        Import.Object(root, "policy");
        string[] allowed = ["requireStrongHash", "requireVersion", "requirePurl", "requireKnownDependencies", "deniedPurls", "deniedLicenseValues", "requireLicense"];
        foreach (var field in root.EnumerateObject())
            if (!allowed.Contains(field.Name, StringComparer.Ordinal)) throw new InputException("Unknown policy field.");
        bool Flag(string name, bool defaultValue = true)
        {
            if (!root.TryGetProperty(name, out var value)) return defaultValue;
            if (value.ValueKind is not (System.Text.Json.JsonValueKind.True or System.Text.Json.JsonValueKind.False))
                throw new InputException("Policy flags must be boolean.");
            return value.GetBoolean();
        }
        string[] List(string name) => Import.Array(root, name).Select(value =>
        {
            if (value.ValueKind != System.Text.Json.JsonValueKind.String || string.IsNullOrWhiteSpace(value.GetString()))
                throw new InputException("Policy lists require nonempty strings.");
            return value.GetString()!;
        }).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        return new(Flag("requireStrongHash"), Flag("requireVersion"), Flag("requirePurl"),
            Flag("requireKnownDependencies"), List("deniedPurls"), List("deniedLicenseValues")) { RequireLicense = Flag("requireLicense", false) };
    }
}
