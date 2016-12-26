"""
Script that loads the basic block coverage information into the IDB
"""
import idc
import idaapi
import idautils

# idaapi.require("tracereader")
# idaapi.require("idahelpers")

from tracereader import TraceReader
from idahelpers import SetBasicBlockColor, rgb_to_bgr, SetFunctionColor

from logging import info, basicConfig, INFO
basicConfig(format='[%(levelname)s] : %(message)s', level=INFO)
from collections import defaultdict

def main():
    info("Showing number of tainted hit per image.")

    # filename = idaapi.askfile_c(0, "pintool.log", "Trace file to load.")
    filename = """/Users/anon/workspace/instrumentation/CodeCoverage/trace.log"""
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
    trace.parse(match_events="HL")

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
    hits = set(filter(lambda x: traced_image.contains(x.address), trace.getBasicBlockHits()))
    hits = set(map(lambda x: image_base + traced_image.get_offset(x.address), hits))

    reached_functions = set()
    for hit in hits:
        f = idaapi.get_func(hit)
        if f:
            if f.startEA in reached_functions:
                continue
            
            info("Reached -> %s" % (GetFunctionName(f.startEA)))
            reached_functions.add(f.startEA)

    if idaapi.askyn_c(1, "Do you want to mark all the FUNCTIONS reached?") == 1:
        FUNCTION_COLOR = rgb_to_bgr(0xBCF5D1)
        for function in reached_functions:
            SetFunctionColor(function, FUNCTION_COLOR)
        
    if idaapi.askyn_c(0, "Do you want to mark all the BASIC BLOCKS reached?") == 1:
        BBLOCK_COLOR = rgb_to_bgr(0xf2ddda)
        for hit in hits:
            SetBasicBlockColor(hit, BBLOCK_COLOR)

if __name__ == "__main__":
    main()