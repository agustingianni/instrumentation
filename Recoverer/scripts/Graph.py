from networkx import MultiGraph, draw_shell
from Recoverer import TraceAnalyzer
import matplotlib.pyplot as plt

def main():
    g = MultiGraph()

    analyzer = TraceAnalyzer()
    analyzer.parse("../pintool.log")

    # Get all the chunks used by the application
    chunks = analyzer.getChunks()
    for chunk in chunks:
        g.add_node("%x-%x" % (chunk.chunk_addr, chunk.timestamp))

    writes = analyzer.getMemoryWrites()
    for write in writes:
        b = "C:%x-%x" % (write.chunk_addr, write.timestamp)
        a = "W:%x-%x" %  (write.write_addr, write.content)
        
        g.add_edge(a, b)

    draw_shell(g)
    plt.show()


if __name__ == '__main__':
    main()