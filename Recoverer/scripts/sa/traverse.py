from collections import deque
import networkx as nx

def bfs(g, start):
    visited = set([start])
    queue = deque([g.neighbors_iter(start)])

    yield start

    while queue:
        try:
            child = next(queue[0])
            if not child in visited:
                visited.add(child)
                queue.append(g.neighbors_iter(child))
                yield child
        except StopIteration:
            queue.popleft()

def dfs_preorder(g, start):
    stack = [g.neighbors_iter(start)]
    visited = set([start])

    yield start

    while stack:
        try:
            child = next(stack[-1])
            if not child in visited:
                visited.add(child)
                stack.append(g.neighbors_iter(child))
                yield child
        except StopIteration:
            stack.pop()

def dfs_postorder(g, start):
    stack = [(start, g.neighbors_iter(start))]
    visited = set([start])

    while stack:
        try:
            child = next(stack[-1][1])
            if not child in visited:
                visited.add(child)
                stack.append((child, g.neighbors_iter(child)))
        except StopIteration:
            yield stack.pop()[0]

def dfs_reverse_postorder(g, start):
    stack = [(start, g.neighbors_iter(start))]
    visited = set([start])
    result = []

    while stack:
        try:
            child = next(stack[-1][1])
            if not child in visited:
                visited.add(child)
                stack.append((child, g.neighbors_iter(child)))
        except StopIteration:
            result.append(stack.pop()[0])

    for i in reversed(result):
        yield i

if __name__ == '__main__':
    g = nx.DiGraph()
    g.add_nodes_from([1,2,3,4,5,6])
    g.add_edges_from(zip("122344566", "213223145"))

#   g = nx.Graph()
#   g.add_edges_from(zip("aaabbbbcce", "cdecdefdff"))

    for i in dfs_preorder(g, '6'):
        print i

    print "POST"
    for i in dfs_postorder(g, '6'):
        print i

    print "REVPOST"
    for i in dfs_reverse_postorder(g, '6'):
        print i

    print "BFS"
    for i in bfs(g, '6'):
        print i
