"""
In order to collect input files run the following command:

    $ find / -name \*.ico -exec cp {} ico/ \;

"""
import os
import shutil
import hashlib

from collections import defaultdict, namedtuple
from logging import info, basicConfig, INFO, error, debug

import idc
import idaapi
from idahelpers import SetFunctionColor, SetBasicBlockColor
from tracereader import TraceReader

CoverageInformation = namedtuple("CoverageInformation", ["trace_file", "hits"])

basicConfig(format='[%(levelname)s] : %(message)s', level=INFO)

def get_image_hits(trace_name, image_name, image_base):
    """
    Return a set of all the hits for the image that matches the 
    parameters.
    """
    # Load the trace file.
    trace = TraceReader(trace_name)
    trace.parse(match_events="HL")   # This will make things quickier, allow H (basic block hit) and L (library loads)

    # Get the loaded images.
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

    return hits

def main():
    # XXX: Change this to the corresponding directory.
    input_dir = "/Users/anon/images/ttf/libFontParser"

    if os.path.isdir(input_dir):
        traces = filter(lambda x: x.endswith(".trace"), map(lambda x: os.path.join(input_dir, x), os.listdir(input_dir)))
    
    else:
        traces = [input_dir]
    
    # Get loaded binary name
    image_name = idc.GetInputFile().lower()
    info("IDB binary name '%s'" % image_name)
        
    # Get the image base
    image_base = idaapi.get_imagebase()
    info("IDB binary base 0x%.16x" % image_base)

    # Gather tuples of 
    coverage_info = []

    for filename in traces:
        debug("Loading code coverage from '%s'." % filename)

        # Get all the hits on this .idb file.
        hits = get_image_hits(filename, image_name, image_base)
        if not len(hits):
            debug("No hits could be loaded from image")
            continue

        # Save the coverage information.
        coverage_info.append(CoverageInformation(filename, hits))

    if not len(coverage_info):
        info("No coverage information was present for image '%s'" % image_name)
        sys.exit()

    all_hits = set()
    shared_hits = set.intersection(*[x.hits for x in coverage_info])
    reached_functions = set()

    for element in coverage_info:
        all_hits.update(element.hits)

        for hit in element.hits:
            f = idaapi.get_func(hit)
            if f:
                reached_functions.add(f.startEA)            

    info("Covered %d basic blocks in total using %d files" % (len(all_hits), len(coverage_info)))
    info("  Number of shared basic locks %d" % (len(shared_hits)))
    info("  Number of reached functions %d" % (len(reached_functions)))

    if idaapi.askyn_c(1, "Do you want to mark all the FUNCTIONS reached?") == 1:
        FUNCTION_COLOR = 0xBCF5D1
        for function in reached_functions:
            info("Reached -> %s" % GetFunctionName(function))
            SetFunctionColor(function, FUNCTION_COLOR)
        
    if idaapi.askyn_c(0, "Do you want to mark all the BASIC BLOCKS reached?") == 1:
        BBLOCK_COLOR_1 = 0xA3A9E3
        BBLOCK_COLOR_2 = 0xA3D1E3
        
        for hit in all_hits:
            SetBasicBlockColor(hit, BBLOCK_COLOR_1)

        for hit in shared_hits:
            SetBasicBlockColor(hit, BBLOCK_COLOR_2)

    return

    trace_to_new = {}

    for filename in traces:
        info("Loading code coverage from '%s'." % filename)

        # Get all the hits on this .idb file.
        hits = get_image_hits(filename, image_name, image_base)
        
        reached_functions = set()
        for e in hits:
            f = idaapi.get_func(e)
            if not f:
                continue

            reached_functions.add(f.startEA)

        # Get the elements that are introduced by this new trace.
        diff_hits = hits - global_hits
        diff_functions = reached_functions - global_reached_functions

        trace_to_new[filename] = diff_functions

        global_hits.update(hits)
        global_reached_functions.update(reached_functions)

    info("Image '%s' got %d hits (global) and %d function hits (global)." % (image_name, len(global_hits), len(global_reached_functions)))

    for trace_name, introduced_functions in trace_to_new.iteritems():
        # Get the original file name.
        file_name = trace_name.replace(".trace", "")

        # We remove the files that did not introduce any new functions.
        if not len(introduced_functions):
            assert os.path.exists(file_name)
            assert os.path.exists(trace_name)

            debug("Removing input file '%s'", os.path.basename(file_name)) 
            debug("Removing trace file '%s'", os.path.basename(trace_name)) 

            os.remove(file_name)
            os.remove(trace_name)
            continue

        fileName, fileExtension = os.path.splitext(file_name)
        fileDir = os.path.dirname(file_name)
        hash_ = hashlib.sha224(file(file_name).read()).hexdigest()

        new_file_name = os.path.join(fileDir, hash_ + fileExtension)
        new_trace_name = new_file_name + ".trace"
        
        os.rename(file_name, new_file_name)
        os.rename(trace_name, new_trace_name)

        info("Trace '%s' introduced functions:" % new_trace_name)
        for func in introduced_functions:
            info("  %s" % GetFunctionName(func))

    if idaapi.askyn_c(1, "Do you want to mark all the FUNCTIONS reached?") == 1:
        FUNCTION_COLOR = 0xBCF5D1
        for function in global_reached_functions:
            SetFunctionColor(function, FUNCTION_COLOR)
        
    if idaapi.askyn_c(0, "Do you want to mark all the BASIC BLOCKS reached?") == 1:
        BBLOCK_COLOR = 0xf2ddda
        for hit in global_hits:
            SetBasicBlockColor(hit, BBLOCK_COLOR)

if __name__ == "__main__":
    main()