namespace Rudy.Chain;

public sealed class Graph
{
    public SortedDictionary<string, string[]> Forward { get; }
    public SortedDictionary<string, string[]> Reverse { get; }
    public Graph(Inventory inventory)
    {
        Forward = new(StringComparer.Ordinal);
        var reverse = inventory.Components.Keys.ToDictionary(k => k, _ => new List<string>(), StringComparer.Ordinal);
        foreach (var id in inventory.Components.Keys)
        {
            Forward[id] = inventory.Dependencies.GetValueOrDefault(id, []);
            foreach (var child in Forward[id]) reverse[child].Add(id);
        }
        Reverse = new(StringComparer.Ordinal);
        foreach (var (id, parents) in reverse) Reverse[id] = parents.Order(StringComparer.Ordinal).ToArray();
    }

    public Dictionary<string, string?> Traverse(string start, bool reverse = false)
    {
        if (!Forward.ContainsKey(start)) throw new InputException("Component ref was not found.");
        var adjacency = reverse ? Reverse : Forward;
        var previous = new Dictionary<string, string?>(StringComparer.Ordinal) { [start] = null };
        var queue = new Queue<string>();
        queue.Enqueue(start);
        while (queue.TryDequeue(out var current))
            foreach (var next in adjacency[current])
                if (previous.TryAdd(next, current)) queue.Enqueue(next);
        return previous;
    }

    public static (string[] Path, bool Truncated) Path(Dictionary<string, string?> previous, string end, int limit = int.MaxValue)
    {
        if (!previous.ContainsKey(end)) return ([], false);
        var path = new List<string>();
        string? current = end;
        while (current is not null && path.Count < limit)
        {
            path.Add(current);
            current = previous[current];
        }
        path.Reverse();
        return (path.ToArray(), current is not null);
    }

    public string[][] Cycles()
    {
        // Iterative Kosaraju avoids process-stack exhaustion on long chains.
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var order = new List<string>();
        foreach (var start in Forward.Keys)
        {
            if (!seen.Add(start)) continue;
            var stack = new Stack<(string Id, int Index)>();
            stack.Push((start, 0));
            while (stack.TryPop(out var frame))
            {
                if (frame.Index == Forward[frame.Id].Length) { order.Add(frame.Id); continue; }
                stack.Push((frame.Id, frame.Index + 1));
                var child = Forward[frame.Id][frame.Index];
                if (seen.Add(child)) stack.Push((child, 0));
            }
        }
        seen.Clear();
        var groups = new List<string[]>();
        for (var i = order.Count - 1; i >= 0; i--)
        {
            var start = order[i];
            if (!seen.Add(start)) continue;
            var group = new List<string>();
            var stack = new Stack<string>();
            stack.Push(start);
            while (stack.TryPop(out var current))
            {
                group.Add(current);
                foreach (var parent in Reverse[current]) if (seen.Add(parent)) stack.Push(parent);
            }
            if (group.Count > 1 || Forward[start].Contains(start, StringComparer.Ordinal))
                groups.Add(group.Order(StringComparer.Ordinal).ToArray());
        }
        return groups.OrderBy(g => g[0], StringComparer.Ordinal).ToArray();
    }
}
