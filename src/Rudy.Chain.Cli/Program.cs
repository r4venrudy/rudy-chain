using Rudy.Chain;

return Run(args);

static int Run(string[] args)
{
    try
    {
        if (args.Length == 1 && args[0] is "--version" or "version")
        { Console.WriteLine("rudy-chain 0.1.0"); return 0; }
        if (args.Length == 0 || (args.Length == 1 && args[0] is "--help" or "help"))
        {
            Console.WriteLine("""
                Rudy Chain 0.1.0 — offline supply-chain review
                audit <bom.json> [--policy <policy.json>] [--format json|sarif] [--fail-on error|warning|none]
                why <bom.json> <bom-ref>       shortest declared root path
                impact <bom.json> <bom-ref>    all declared reverse dependents
                diff <before.json> <after.json>
                Exit: 0 success, 1 policy threshold reached, 2 input/usage/I/O error.
                """);
            return 0;
        }
        if (args[0] == "audit" && args.Length >= 2)
        {
            var options = new Dictionary<string, string>(StringComparer.Ordinal);
            for (var i = 2; i < args.Length; i += 2)
            {
                if (i + 1 >= args.Length || args[i] is not ("--policy" or "--format" or "--fail-on") || !options.TryAdd(args[i], args[i + 1]))
                    throw new InputException("Invalid or duplicate audit option.");
            }
            var format = options.GetValueOrDefault("--format", "json");
            var failOn = options.GetValueOrDefault("--fail-on", "error");
            if (format is not ("json" or "sarif") || failOn is not ("error" or "warning" or "none"))
                throw new InputException("Unsupported format or failure threshold.");
            var policy = options.TryGetValue("--policy", out var file) ? Policy.Load(file) : Policy.Default;
            var report = Analysis.Audit(Import.Load(args[1]), policy);
            Console.WriteLine(JsonOutput.Serialize(format == "sarif" ? Sarif.Export(report) : report));
            return report.Findings.Any(f => failOn == "error" ? f.Level == "error" : failOn == "warning" && f.Level is "error" or "warning") ? 1 : 0;
        }
        if (args[0] == "diff" && args.Length == 3)
        { Console.WriteLine(JsonOutput.Serialize(Analysis.Diff(Import.Load(args[1]), Import.Load(args[2])))); return 0; }
        if (args[0] is "why" or "impact" && args.Length == 3)
        {
            var bom = Import.Load(args[1]);
            var graph = new Graph(bom);
            if (!bom.Components.ContainsKey(args[2])) throw new InputException("Component ref was not found.");
            var unknown = bom.Components.Keys.Where(k => !bom.Dependencies.ContainsKey(k)).ToArray();
            if (args[0] == "why")
            {
                var path = Graph.Path(graph.Traverse(bom.Root), args[2]);
                Console.WriteLine(JsonOutput.Serialize(new { schema = "rudy-chain/path/v1", bom.Digest, root = bom.Root,
                    target = args[2], declaredReachable = path.Path.Length > 0, path = path.Path,
                    unknownDependencyRecords = unknown, notices = bom.Notices }));
            }
            else
            {
                var ancestors = graph.Traverse(args[2], reverse: true);
                Console.WriteLine(JsonOutput.Serialize(new { schema = "rudy-chain/impact/v1", bom.Digest, target = args[2],
                    dependents = ancestors.Keys.Where(k => k != args[2]).Order(StringComparer.Ordinal).ToArray(),
                    unknownDependencyRecords = unknown, notices = bom.Notices }));
            }
            return 0;
        }
        throw new InputException("Invalid command. Use --help.");
    }
    catch (Exception ex) when (ex is InputException or IOException or UnauthorizedAccessException)
    {
        // Input text and paths are not echoed into terminal diagnostics.
        Console.Error.WriteLine(ex is InputException ? ex.Message : "Unable to read input or write output.");
        return 2;
    }
}
