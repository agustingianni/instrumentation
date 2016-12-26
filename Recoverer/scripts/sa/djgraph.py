import networkx as nx
from itertools import chain
from networkx.algorithms.components import strongly_connected_components
from dominator import get_dominators

class DJLoop(list):
    def __init__(self, reducible=True):
        self.reducible = reducible
        self.entries = set()

class DJGraph(nx.DiGraph):
    def __init__(self, g=None, start=None):
        """
        Given a DiGraph and a starting vertex, construct a DJ graph.

        @type g: A DiGraph
        @param g: The flowgraph to process

        @type start: Any
        @param: The starting vertex of g

        @return: A DJ graph corresponding to the flowgraph g.
        """

        nx.DiGraph.__init__(self)

        if start != None:
            self.set_start(start)

        if g == None:
            return

        if start == None:
            raise Exception("start node expected")

        doms = get_dominators(g, start)

        # Add all D-edges.  The graph now holds the dominator tree.
        for (k, v) in doms.items():
            if k != v:
                self.add_edge(v, k, dom = True)

        # Update the level values of the dominator tree.
        self.update_levels()

        # Add all J-edges.
        for e in g.edges_iter():
            if doms[e[1]] != e[0]:
                self.add_edge(e[0], e[1], join = True)

        # Mark all sp-back edges.
        self.update_sp_backedges()

    def collapse(self, v, w):
        if not self.has_edge(v, w) or self.in_degree(w) != 1 or w == self.start:
            return False

        for x in self.successors_iter(w):
            self.add_edge(v, x)

        for x in self.predecessors_iter(w):
            self.add_edge(x, v)

        self.remove_node(w)
        return True

    def collapse_set(self, v, s):
        result = DJLoop()
        s_in_vertices  = []
        s_out_vertices = []

        for vertex in s:
            for n in self.predecessors_iter(vertex):
                if n not in s:
                    s_in_vertices.append((n, self.get_edge_data(n, vertex)))

            for n in self.successors_iter(vertex):
                if n not in s:
                    s_out_vertices.append((n, self.get_edge_data(vertex, n)))

            if 'collapsed' in self.node[vertex]:
                result.append(self.node[vertex]['collapsed'])
            else:
                result.append(vertex)

            if vertex != v:
                self.remove_node(vertex)

        for i in s_in_vertices:
            self.add_edge(i[0], v, i[1])

        for i in s_out_vertices:
            self.add_edge(v, i[0], i[1])

        self.node[v]['collapsed'] = result
        return result

    def set_start(self, start):
        self.start = start

    def get_loops(self):
        lvlmap = self.get_level_map()
        result = []

        for i in xrange(len(lvlmap) - 1, -1, -1):
            irreducible = False

            for n in lvlmap[i]:
                for e in self.in_edges(n):
                    if not self.has_edge(*e):
                        continue
                    if self.is_cj_edge(e) and self.is_sp_back_edge(e):
                        irreducible = True
                    elif self.is_bj_edge(e):
                        cs = self.reach_under(e[1]) | set([n])
                        ret = self.collapse_set(n, cs)
                        ret.entries.add(n)
                        result.append(ret)

                if irreducible:
                    j = chain(*(lvlmap[i] for i in xrange(i, len(lvlmap))))
                    for scc in strongly_connected_components(self.subgraph(j)):
                        if len(scc) > 1:
                            e = [e for e in scc if self.node[e]['level'] == i]
                            ret = self.collapse_set(min(scc), scc)
                            ret.entries = set(e)
                            ret.reducible = False
                            result.append(ret)

        return result

    def get_level_map(self):
        lvlmap = {}

        for n in self.nodes_iter():
            if self.node[n]['level'] in lvlmap:
                lvlmap[self.node[n]['level']].append(n)
            else:
                lvlmap[self.node[n]['level']] = [n]

        return lvlmap

    def update_levels(self):
        stack = [self.d_neighbors_iter(self.start)]
        level = 0

        self.node[self.start]['level'] = level

        while stack:
            try:
                child = next(stack[-1])
                level += 1
                self.node[child]['level'] = level
                stack.append(self.d_neighbors_iter(child))
            except StopIteration:
                stack.pop()
                level -= 1

    def idom(self, x):
        i = (p[0] for p in self.in_edges_iter(x)
             if self.get_edge_data(*p).get('dom', False))
        return next(i)

    def dom(self, x, y):
        while True:
            if x == y:
                return True

            try:
                y = self.idom(y)
            except StopIteration: 
                return False

    def stdom(self, x, y):
        if x == y:
            return False

        return self.dom(x, y)

    def is_bj_edge(self, e):
        return 'join' in self.get_edge_data(*e) and self.dom(e[1], e[0])

    def is_cj_edge(self, e):
        return 'join' in self.get_edge_data(*e) and not self.dom(e[1], e[0])

    def is_sp_back_edge(self, e):
        return 'sp-back' in self.get_edge_data(*e)

    def d_neighbors_iter(self, n):
        return (p[1] for p in self.out_edges_iter(n)
                     if 'dom' in self.get_edge_data(*p))

    def j_neighbors_iter(self, n):
        return (p[1] for p in self.out_edges_iter(n)
                     if 'join' in self.get_edge_data(*p))

    def bj_predecessors_iter(self, n):
        return (p[0] for p in self.in_edges_iter(n) if self.is_bj_edge(p))

    def sp_back_predecessors_iter(self, n):
        return (p[0] for p in self.in_edges_iter(n) if self.is_sp_back_edge(p))

    def update_sp_backedges(self):
        for e in self.get_sp_backedges_iter():
            self[e[0]][e[1]]['sp-back'] = True

    def get_sp_backedges_iter(self):
        stack = [(self.start, self.neighbors_iter(self.start))]
        tree = set([self.start])
        visited = set([self.start])

        while stack:
            current, i = stack[-1]
            tree.add(current)

            try:
                child = next(i)
                if not child in visited:
                    visited.add(child)
                    stack.append((child, self.neighbors_iter(child)))
                elif child in tree:
                    yield current, child
            except StopIteration:
                child = stack.pop()
                tree.remove(child[0])
                
    def reach_under(self, n):
        """
        Find all nodes that can reach the source nodes of BJ edges
        incident on the loop header n, without going through n.

        Note that this routine works on BJ edges only, and does not work
        on sp-back edges.  This is because the DJ-graph loop identification
        algorithm will only calculate ReachUnder(n) for all BJ-edges to n.
        This implies that the sources of these edges are all dominated by n,
        and as such will never include paths that do not have all their
        vertices as proper descendants of n.
        
        @type n: Vertex
        @param n: A vertex representing the head of a loop
        
        @rtype: Set
        """
        result = set()

        for p in self.bj_predecessors_iter(n):
            stack = [self.predecessors_iter(p)]
            visited = set([p])

            while stack:
                try:
                    child = next(stack[-1])
                    if not child in visited and child != n:
                        visited.add(child)
                        stack.append(self.predecessors_iter(child))
                except StopIteration:
                    stack.pop()

            result = result | visited

        return result
