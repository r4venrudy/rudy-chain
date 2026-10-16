using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Rudy.Chain;

public static class Import
{
    public const int MaxBytes = 16 * 1024 * 1024;
    public const int MaxComponents = 10_000;
    public const int MaxEdges = 100_000;

    public static byte[] ReadBounded(string path, int limit = MaxBytes)
    {
        using var file = File.OpenRead(path);
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        int count;
        while ((count = file.Read(chunk)) > 0)
        {
            if (buffer.Length + count > limit) throw new InputException($"Input exceeds {limit} bytes.");
            buffer.Write(chunk, 0, count);
        }
        return buffer.ToArray();
    }

    public static JsonDocument ReadJson(byte[] bytes, int limit = MaxBytes)
    {
        if (bytes.Length > limit) throw new InputException($"Input exceeds {limit} bytes.");
        try { _ = new UTF8Encoding(false, true).GetCharCount(bytes); }
        catch (DecoderFallbackException) { throw new InputException("Input must be valid UTF-8."); }
        try
        {
            // Accept a UTF-8 BOM, but never decode other encodings implicitly.
            var offset = bytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }) ? 3 : 0;
            var doc = JsonDocument.Parse(bytes.AsMemory(offset), new JsonDocumentOptions { MaxDepth = 64 });
            try
            {
                var pending = new Stack<JsonElement>();
                pending.Push(doc.RootElement);
                var nodes = 0;
                while (pending.TryPop(out var value))
                {
                    if (++nodes > 500_000) throw new InputException("JSON node limit exceeded.");
                    if (value.ValueKind == JsonValueKind.Object)
                    {
                        var names = new HashSet<string>(StringComparer.Ordinal);
                        foreach (var p in value.EnumerateObject())
                        {
                            if (p.Name.Length > 8192 || !names.Add(p.Name))
                                throw new InputException("Duplicate or oversized JSON property.");
                            pending.Push(p.Value);
                        }
                    }
                    else if (value.ValueKind == JsonValueKind.Array)
                        foreach (var item in value.EnumerateArray()) pending.Push(item);
                    else if (value.ValueKind == JsonValueKind.String && value.GetString()!.Length > 8192)
                        throw new InputException("JSON string limit exceeded.");
                }
                return doc;
            }
            catch { doc.Dispose(); throw; }
        }
        catch (JsonException) { throw new InputException("Malformed JSON or depth limit exceeded."); }
    }

    internal static void Object(JsonElement value, string label)
    {
        if (value.ValueKind != JsonValueKind.Object) throw new InputException($"{label} must be an object.");
    }
    internal static string Text(JsonElement value, string name, bool required = false)
    {
        if (!value.TryGetProperty(name, out var field))
        {
            if (required) throw new InputException($"Missing {name}.");
            return "";
        }
        if (field.ValueKind != JsonValueKind.String) throw new InputException($"{name} must be a string.");
        var text = field.GetString()!;
        if (required && string.IsNullOrWhiteSpace(text)) throw new InputException($"Empty {name}.");
        return text;
    }
    internal static JsonElement[] Array(JsonElement value, string name)
    {
        if (!value.TryGetProperty(name, out var field)) return [];
        if (field.ValueKind != JsonValueKind.Array) throw new InputException($"{name} must be an array.");
        return field.EnumerateArray().ToArray();
    }

    public static Inventory Load(string path) => Parse(ReadBounded(path));
    public static Inventory Parse(byte[] bytes)
    {
        using var doc = ReadJson(bytes);
        var root = doc.RootElement;
        Object(root, "BOM");
        if (Text(root, "bomFormat", true) != "CycloneDX") throw new InputException("Expected a CycloneDX JSON BOM.");
        var spec = Text(root, "specVersion", true);
        if (spec is not ("1.5" or "1.6" or "1.7")) throw new InputException("Supported CycloneDX versions: 1.5, 1.6, 1.7.");
        if (Array(root, "services").Length > 0) throw new InputException("Service graphs are not supported; use a component-only BOM.");
        if (!root.TryGetProperty("metadata", out var metadata)) throw new InputException("metadata.component with bom-ref is required.");
        Object(metadata, "metadata");
        if (!metadata.TryGetProperty("component", out var application)) throw new InputException("metadata.component is required.");

        var components = new SortedDictionary<string, Component>(StringComparer.Ordinal);
        var stack = new Stack<JsonElement>();
        stack.Push(application);
        foreach (var item in Array(root, "components")) stack.Push(item);
        while (stack.TryPop(out var item))
        {
            Object(item, "component");
            var id = Text(item, "bom-ref", true);
            var hashes = new SortedDictionary<string, string>(StringComparer.Ordinal);
            foreach (var hash in Array(item, "hashes"))
            {
                Object(hash, "hash");
                var alg = Text(hash, "alg", true);
                var content = Text(hash, "content", true).ToLowerInvariant();
                var length = alg switch { "SHA-256" => 64, "SHA-384" => 96, "SHA-512" => 128, _ => 0 };
                if (length > 0 && (content.Length != length || !content.All(Uri.IsHexDigit)))
                    throw new InputException("Invalid strong hash encoding.");
                if (!hashes.TryAdd(alg, content)) throw new InputException("Duplicate hash algorithm.");
            }
            var licenses = new SortedSet<string>(StringComparer.Ordinal);
            foreach (var license in Array(item, "licenses"))
            {
                Object(license, "license choice");
                if (license.TryGetProperty("expression", out _) && license.TryGetProperty("license", out _))
                    throw new InputException("Ambiguous license choice.");
                if (license.TryGetProperty("expression", out _))
                    licenses.Add(Text(license, "expression", true));
                else if (license.TryGetProperty("license", out var details))
                {
                    Object(details, "license");
                    var idValue = Text(details, "id");
                    licenses.Add(idValue.Length > 0 ? idValue : Text(details, "name", true));
                }
                else throw new InputException("Unsupported license choice.");
            }
            var component = new Component(id, Text(item, "type", true), Text(item, "group"),
                Text(item, "name", true), Text(item, "version"), Text(item, "purl"),
                Text(item, "scope"), licenses.ToArray(), hashes);
            if (components.Count >= MaxComponents) throw new InputException("Component limit exceeded.");
            if (!components.TryAdd(id, component)) throw new InputException("Duplicate bom-ref.");
            foreach (var child in Array(item, "components")) stack.Push(child);
        }
        var dependencies = new SortedDictionary<string, string[]>(StringComparer.Ordinal);
        var edges = 0;
        foreach (var dep in Array(root, "dependencies"))
        {
            Object(dep, "dependency");
            var source = Text(dep, "ref", true);
            if (!components.ContainsKey(source)) throw new InputException("Unknown dependency ref.");
            if (Array(dep, "provides").Length > 0) throw new InputException("provides edges are not supported.");
            var targets = new SortedSet<string>(StringComparer.Ordinal);
            foreach (var target in Array(dep, "dependsOn"))
            {
                if (target.ValueKind != JsonValueKind.String || !components.ContainsKey(target.GetString()!))
                    throw new InputException("Unknown or invalid dependency target.");
                if (++edges > MaxEdges) throw new InputException("Dependency edge limit exceeded.");
                if (!targets.Add(target.GetString()!)) throw new InputException("Duplicate dependency edge.");
            }
            if (!dependencies.TryAdd(source, targets.ToArray())) throw new InputException("Duplicate dependency record.");
        }
        var notices = new List<string>
        {
            "Declared dependency paths do not prove runtime reachability or exploitability.",
            "A hash is a declaration, not verification of package bytes or publisher identity."
        };
        if (Array(root, "compositions").Length > 0) notices.Add("Composition completeness statements are not interpreted.");
        if (Array(root, "vulnerabilities").Length > 0) notices.Add("Embedded vulnerability assertions are not evaluated; no CVE feed is queried.");
        return new Inventory(Convert.ToHexStringLower(SHA256.HashData(bytes)), spec,
            Text(application, "bom-ref", true), components, dependencies, notices.ToArray());
    }

    public static Inventory Parse(string text) => Parse(Encoding.UTF8.GetBytes(text));
}
