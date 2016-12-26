from traverse import dfs_reverse_postorder
from utils import get_postorder_numbering
    
def get_dominators(g, start):
    """
    Get the immediate dominator tree for g
    
    @type g: Graph
    @param g: The graph to process
    
    @type start: Any
    @param: The starting vertex of g
    
    @return: The dominator tree for g as a dictionary mapping each vertex 
        to its immediate dominator 
    """
    
    pnum = get_postorder_numbering(g, start)
    changed = True
    doms = { start: start }

    def intersect(b1, b2):
        finger1, finger2 = b1, b2

        while pnum[finger1] != pnum[finger2]:
            while pnum[finger1] < pnum[finger2]:
                finger1 = doms[finger1]
            while pnum[finger2] < pnum[finger1]:
                finger2 = doms[finger2]

        return finger1

    while changed:
        changed = False

        for b in (b for b in dfs_reverse_postorder(g, start) if b != start):
            # Find the first processed predecessor of b.
            new_idom = next(p for p in g.predecessors_iter(b) if p in doms)

            for p in g.predecessors(b):
                if p in doms and p != new_idom:
                    new_idom = intersect(p, new_idom)

            if b not in doms or doms[b] != new_idom:
                doms[b] = new_idom
                changed = True

    return doms
