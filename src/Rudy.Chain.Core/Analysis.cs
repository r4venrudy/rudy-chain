namespace Rudy.Chain;

public static class Analysis
{
    public static AuditReport Audit(Inventory inventory, Policy? policy = null)
    {
        policy ??= Policy.Default;
        var graph = new Graph(inventory);
        var previous = graph.Traverse(inventory.Root);
        var findings = new List<Finding>();
        var denied = new HashSet<string>(policy.DeniedPurls, StringComparer.Ordinal);
        var licenses = new HashSet<string>(policy.DeniedLicenseValues, StringComparer.Ordinal);
        void Add(string code, string level, string id, string message)
        {
            var path = Graph.Path(previous, id, 32);
            findings.Add(new(code, level, id, message, path.Path, path.Truncated));
        }
        foreach (var (id, item) in inventory.Components)
        {
            if (policy.RequireStrongHash && !item.HasStrongHash)
                Add("CHAIN001", "warning", id, "No declared SHA-256, SHA-384 or SHA-512 digest.");
            if (policy.RequireVersion && string.IsNullOrWhiteSpace(item.Version))
                Add("CHAIN002", "warning", id, "No component version is declared.");
            if (policy.RequirePurl && string.IsNullOrWhiteSpace(item.Purl))
                Add("CHAIN003", "warning", id, "No package URL is declared.");
            if (policy.RequireKnownDependencies && !inventory.Dependencies.ContainsKey(id))
                Add("CHAIN004", "warning", id, "Dependency record omitted: dependencies are unknown, not an asserted empty leaf.");
            if (!previous.ContainsKey(id))
                Add("CHAIN005", "note", id, "No declared dependency path from the BOM root; incomplete graphs may omit real paths.");
            if (denied.Contains(item.Purl)) Add("CHAIN007", "error", id, "Exact package URL is denied by the supplied policy.");
            if (item.Licenses.Any(licenses.Contains))
                Add("CHAIN009", "error", id, "A complete declared license value exactly matches the supplied deny list.");
        }
        var cycles = graph.Cycles();
        foreach (var group in cycles) Add("CHAIN006", "note", group[0], "Declared dependency cycle; see the cycles section for its strongly connected component.");

        foreach (var group in inventory.Components.Values.Where(c => c.Purl.Length > 0).GroupBy(c => c.Purl, StringComparer.Ordinal))
        {
            var conflicts = group.SelectMany(c => c.Hashes.Where(h => h.Key is "SHA-256" or "SHA-384" or "SHA-512"))
                .GroupBy(h => h.Key, StringComparer.Ordinal).Any(h => h.Select(x => x.Value).Distinct(StringComparer.Ordinal).Count() > 1);
            if (conflicts)
                foreach (var item in group) Add("CHAIN008", "error", item.Ref, "Identical package URLs declare conflicting digests for the same strong hash algorithm.");
        }
        return new("rudy-chain/audit/v1", "0.1.0", inventory.Digest, inventory.Root,
            inventory.Components.Count, graph.Forward.Values.Sum(e => e.Length), previous.Count,
            inventory.Components.Count - inventory.Dependencies.Count, cycles, inventory.Notices,
            findings.OrderBy(f => f.RuleId, StringComparer.Ordinal).ThenBy(f => f.ComponentRef, StringComparer.Ordinal).ToArray());
    }

    public static DiffReport Diff(Inventory before, Inventory after)
    {
        static Dictionary<string, Component[]> Packages(Inventory bom) => bom.Components.Values
            .GroupBy(c => c.PackageKey, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.OrderBy(c => c.Variant, StringComparer.Ordinal).ToArray(), StringComparer.Ordinal);
        static SortedDictionary<string, DependencyEdge> Edges(Inventory bom)
        {
            var edges = new SortedDictionary<string, DependencyEdge>(StringComparer.Ordinal);
            foreach (var (source, targets) in bom.Dependencies)
                foreach (var target in targets)
                {
                    var edge = new DependencyEdge(bom.Components[source].Coordinate, bom.Components[target].Coordinate);
                    edges.TryAdd(System.Text.Json.JsonSerializer.Serialize(edge), edge);
                }
            return edges;
        }
        var a = Packages(before);
        var b = Packages(after);
        var added = new List<PackageChange>();
        var removed = new List<PackageChange>();
        var changed = new List<PackageChange>();
        foreach (var key in a.Keys.Union(b.Keys, StringComparer.Ordinal).Order(StringComparer.Ordinal))
        {
            var item = a.GetValueOrDefault(key, b.GetValueOrDefault(key, []))[0];
            var identity = new PackageIdentity(item.Type, item.Group, item.Name);
            if (!a.TryGetValue(key, out var old)) added.Add(new(identity, [], b[key].Select(c => c.Snapshot).ToArray()));
            else if (!b.TryGetValue(key, out var next)) removed.Add(new(identity, old.Select(c => c.Snapshot).ToArray(), []));
            else if (!old.Select(c => c.Variant).SequenceEqual(next.Select(c => c.Variant), StringComparer.Ordinal))
                changed.Add(new(identity, old.Select(c => c.Snapshot).ToArray(), next.Select(c => c.Snapshot).ToArray()));
        }
        var edgesA = Edges(before);
        var edgesB = Edges(after);
        static PackageCoordinate[] Unknown(Inventory bom) => bom.Components.Values.Where(c => !bom.Dependencies.ContainsKey(c.Ref))
            .OrderBy(c => c.EdgeKey, StringComparer.Ordinal).Select(c => c.Coordinate).ToArray();
        return new("rudy-chain/diff/v1", before.Digest, after.Digest,
            before.Components[before.Root].Coordinate, after.Components[after.Root].Coordinate,
            added.ToArray(), removed.ToArray(), changed.ToArray(),
            edgesB.Keys.Except(edgesA.Keys, StringComparer.Ordinal).Select(k => edgesB[k]).ToArray(),
            edgesA.Keys.Except(edgesB.Keys, StringComparer.Ordinal).Select(k => edgesA[k]).ToArray(),
            Unknown(before), Unknown(after), ["Package groups use type, group and name; all declared variants are retained.",
                "Renaming bom-ref values alone does not change package or edge identities.",
                "Absent inventory entries do not establish that software was removed from a deployed system."]);
    }
}
