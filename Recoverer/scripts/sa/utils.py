from collections import deque
from traverse import dfs_postorder, dfs_reverse_postorder

def median(l, sort=True):
    if not l:
        return []

    if sort:
        l = sorted(l)

    i, j = (len(l) - 1) / 2, len(l) / 2
    if i == j:
        return [l[i]]

    return [l[i], l[j]]

def digraph_edge_invert(g, edge):
    """
    Invert an edge in a directed graph.
    
    @type g: networkx.DiGraph
    @param g: The graph to process
    
    @type start: Any
    @param start: The first vertex in g
    
    @return: A generator for the backedges of g
    @rtype: Generator
    """

    # XXX: What do we do with the copied attributes if the inverted edge
    # already exists (cycle)?
    g.succ[edge[1]][edge[0]] = g.succ[edge[0]][edge[1]]
    g.pred[edge[0]][edge[1]] = g.pred[edge[1]][edge[0]]
    del g.succ[edge[0]][edge[1]]
    del g.pred[edge[1]][edge[0]]

def get_backedges_iter(g, start):
    """
    Iterate over backward edges in g
    
    @type g: networkx.Graph
    @param g: The graph to process
    
    @type start: Any
    @param start: The first vertex in g
    
    @return: A generator for the backedges of g
    @rtype: Generator
    """
    stack = [(start, g.neighbors_iter(start))]
    tree = set([start])
    visited = set([start])

    while stack:
        current, i = stack[-1]
        tree.add(current)

        try:
            child = next(i)
            if not child in visited:
                visited.add(child)
                stack.append((child, g.neighbors_iter(child)))
            elif child in tree:
                yield current, child
        except StopIteration:
            child = stack.pop()
            tree.remove(child[0])

def get_backedges(g, start):
    return list(get_backedges_iter(g, start))

def get_postorder_numbering(g, start):
    """
    Generate a postorder numbering for g
    
    @type g: networkx.Graph
    @param g: The graph to process
    
    @type start: Any
    @param start: The first vertex in g
    
    @return: The postorder numbering for g
    @rtype: Dict
    """
    
    res = {}
    cnt = 0
    
    for vertex in dfs_postorder(g, start):
        res[vertex] = cnt 
        cnt += 1
        
    return res

def get_reverse_postorder_numbering(g, start):
    """
    Generate a reverse postorder numbering for g
    
    @type g: networkx.Graph
    @param g: The graph to process
    
    @type start: Any
    @param start: The first vertex in g
    
    @return: The reverse postorder numbering for g
    @rtype: Dict
    """
    
    res = {}
    cnt = 0
    
    for vertex in dfs_reverse_postorder(g, start):
        res[vertex] = cnt 
        cnt += 1
        
    return res

def get_longest_path_layering(g):
    inverted_edges = set([])
    removed_nodes = set([])

    # We invert the back edges in the graph.
    start = [n for n in g.nodes() if g.in_degree(n) == 0]
    for start_node in start:
        for edge in get_backedges(g, start_node):
            inverted_edges.add(edge)
            digraph_edge_invert(g, edge)

    # Process the graph with inverted edges.
    queue = deque(start)
    queue_next = deque()
    level = 0
    res = []

    while queue or queue_next:
        try:
            child = queue.popleft()
            try:
                res[level].append(child)
            except IndexError:
                res.append([child])

            outstar_child = g.neighbors(child)
            removed_nodes.add(child)

            for n in g.neighbors(child):
                l = [e for e in g.predecessors(n) if e not in removed_nodes]
                if len(l) == 0:
                    queue_next.append(n)
        except IndexError:
            level += 1
            queue, queue_next = queue_next, queue

    # Invert the edges we have inverted previously back again.
    for e in inverted_edges:
        digraph_edge_invert(g, tuple(reversed(e)))
    
    return res

def layering_to_rank_map(layering):
    ranks = {}

    for i, l in enumerate(layering):
        for e in l:
            ranks[e] = i

    return ranks
