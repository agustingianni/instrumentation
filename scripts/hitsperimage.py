from tracereader import TraceReader
from logging import info, basicConfig, INFO
basicConfig(format='[%(levelname)s] : %(message)s', level=INFO)

def main():
    info("Showing number of basic blocks hit per image.")

    # filename = idaapi.askfile_c(0, "pintool.log", "Trace file to load.")
    filename = """/Users/anon/workspace/instrumentation/CodeCoverage/trace.log"""
    if filename is None:
        info("Aborting ...")

    # Load the trace file.
    trace = TraceReader(filename)
    trace.parse(match_events="HL")   # This will make things quickier, allow H (basic block hit) and L (library loads)

    from collections import defaultdict
    count = defaultdict(int)

    working_set = trace.getBasicBlockHits()
    for image in trace.getLoadedImages():
        for bblock in working_set:
            if image.contains(bblock.address):
                count[image.name] += 1

    import operator
    sorted_x = sorted(count.items(), key=operator.itemgetter(1))
    for a in sorted_x:
        print "0x%.8x hits in %s" % (a[1], a[0])

if __name__ == "__main__":
    main()