"""
Script that loads the taint information into the IDB
"""
import idc
import idaapi
import idautils

idaapi.require("tracereader")
idaapi.require("idahelpers")

from tracereader import TraceReader
from idahelpers import SetInstructionColor, rgb_to_bgr

from logging import info, basicConfig, INFO
basicConfig(format='[%(levelname)s] : %(message)s', level=INFO)
from collections import defaultdict


TAINTED_COLOR = rgb_to_bgr(0xFC8B8B)

def main():
    info("Showing number of tainted hit per image.")

    # filename = idaapi.askfile_c(0, "pintool.log", "Trace file to load.")
    filename = """/Users/anon/workspace/instrumentation/Pinnacle/taint.log"""
    if filename is None:
        info("Aborting ...")
        return

    # Get loaded binary name
    image_name = idc.GetInputFile().lower()
    info("IDB binary name '%s'" % image_name)
        
    # Get the image base
    image_base = idaapi.get_imagebase()
    info("IDB binary base 0x%.16x" % image_base)

    # Load the trace file.
    trace = TraceReader(filename)
    trace.parse(match_events="TL")

    # The IDB matches one and only one loaded image. Find it.
    traced_image = None
    for image in trace.getLoadedImages():
        if image_name.lower() in os.path.basename(image.name).lower():
            traced_image = image
            break

    if not traced_image:
        info("Error, could not find the traced image '%s' in the list of loaded images." % image_name)
        return set()

    # Collect all the hits that belong to the ida database.
    hits = set(filter(lambda x: traced_image.contains(x.address), trace.getTaintedInstructions()))
    hits = set(map(lambda x: image_base + traced_image.get_offset(x.address), hits))

    for hit in hits:
        SetInstructionColor(hit, TAINTED_COLOR)

    reached_functions = set()
    for hit in filter(lambda x: traced_image.contains(x.address), trace.getTaintedInstructions()):
        f = idaapi.get_func(hit.address)
        if f:
            if f.startEA in reached_functions:
                continue
            
            info("Reached -> 0x%.16x : %s " % (f.startEA, GetFunctionName(f.startEA)))
            reached_functions.add(f.startEA)

if __name__ == "__main__":
    main()