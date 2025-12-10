
class AttackGraph:
    def __init__(self, assets, start_nodes, goal_nodes, edges):
        self.assets = set(assets) | set(start_nodes) | set(goal_nodes)
        self.start_nodes = set(start_nodes)
        self.goal_nodes = set(goal_nodes)
        self.edges = edges
        self.adj = {}
        for e in edges:
            src = e["src"]
            self.adj.setdefault(src, []).append(e)

    def neighbors(self, node):
        return self.adj.get(node, [])

    def enumerate_paths(self, max_depth=5):
        paths = []
        for s in self.start_nodes:
            self._dfs(current=s, path=[], seen={s}, paths=paths, max_depth=max_depth)
        return paths

    def _dfs(self, current, path, seen, paths, max_depth):
        if len(path) > max_depth:
            return

        if current in self.goal_nodes:
            paths.append(path.copy())
            return

        for e in self.neighbors(current):
            nxt = e["dst"]
            if nxt in seen and nxt not in self.goal_nodes:
                continue

            seen.add(nxt)
            path.append(e)
            self._dfs(nxt, path, seen, paths, max_depth)
            path.pop()
            seen.discard(nxt)

