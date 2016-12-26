"""
Script that prints the ammount of tainted instructions
per loaded module.
"""
from tracereader import TraceReader
from logging import info, basicConfig, INFO
basicConfig(format='[%(levelname)s] : %(message)s', level=INFO)

from collections import defaultdict

def main():
    info("Showing number of tainted hit per image.")

    # filename = idaapi.askfile_c(0, "pintool.log", "Trace file to load.")
    filename = """/Users/anon/workspace/instrumentation/Pinnacle/taint.log"""
    # filename = """/Users/anon/images/tiff2/12.tiff.trace"""
    if filename is None:
        info("Aborting ...")

    # Load the trace file.
    trace = TraceReader(filename)
    trace.parse(match_events="TL")

    count = defaultdict(int)

    working_set = trace.getTaintedInstructions()
    for image in trace.getLoadedImages():
        for tainted_ins in working_set:
            if image.contains(tainted_ins.address):
                count[image.name] += 1

    import operator
    sorted_x = sorted(count.items(), key=operator.itemgetter(1))
    for a in sorted_x:
        print "0x%.8x tainted instructions in %s" % (a[1], a[0])

if __name__ == "__main__":
    main()