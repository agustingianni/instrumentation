"""
Given a directory with .trace files calculate the minimum set
of files that gives you the most coverage.

It does not destroy the input directory, it just creates a new
directory with the name of the library you are getting coverage
for.
"""

import os
import shutil
import hashlib

from collections import defaultdict, namedtuple
from logging import info, basicConfig, INFO, error, debug

from tracereader import TraceReader

CoverageInformation = namedtuple("CoverageInformation", ["trace_file", "hits"])

basicConfig(format='[%(levelname)s] : %(message)s', level=INFO)

def __get_biggest__(cur_max_set, input_sets):
    """
    Given a 'cur_max_set' that contains the current maximum basic block hits
    return the set that belongs to 'input_sets' that adds the most new elements
    to the 'cur_max_set' set.

    Returns None if there is none.
    """
    biggest_set = None
    for input_set in input_sets:
        if not biggest_set or (len(input_set.hits - cur_max_set) > len(biggest_set.hits)):
            biggest_set = input_set

    return biggest_set

def set_coverage(input_sets):
    """
    Given a 'input_sets' consisting of a list of CoverageInformation objects
    return a list of the minimum set of input files that maximize code coverage.
    """
    # Save a list of all the CoverageInformation instances that maximize the coverage.
    winner_list = []

    cur_max_set = set()
    while True:
        # From the list of inputs pick the one that adds the most hits.
        ret = __get_biggest__(cur_max_set, input_sets)
        if not ret:
            break

        # Update the max set.
        t = len(cur_max_set)
        cur_max_set.update(ret.hits)
        
        # This is shit, why the fuck this is failing?.
        if t != len(cur_max_set):
            # Save the CoverageInformation object.
            winner_list.append(ret)

            debug("%d -> %d" % (t, len(cur_max_set)))

        # Remove it from the working set.
        input_sets.remove(ret)

    return winner_list

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
    input_dir = "/Users/anon/images/ttf"
    traces = filter(lambda x: x.endswith(".trace"), map(lambda x: os.path.join(input_dir, x), os.listdir(input_dir)))
    
    # Get loaded binary name
    image_name = "libFontParser"
    info("Getting coverage information for binary name '%s'" % image_name)
        
    # Create the destination directory.
    dest_directory = os.path.join(input_dir, image_name)
    os.makedirs(dest_directory)

    info("Saving resutls to '%s'" % dest_directory)

    # Get the image base
    image_base = 0x00007fff91c6b000

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

    filtered_coverage_set = set_coverage(coverage_info)

    all_hits = set()
    shared_hits = set.intersection(*[x.hits for x in filtered_coverage_set])
    reached_functions = set()

    for element in filtered_coverage_set:
        info("File '%s' adds %d new hits" % (element.trace_file, len(element.hits)))
        
        shutil.copy(element.trace_file, dest_directory)
        shutil.copy(element.trace_file.replace(".trace", ""), dest_directory)
        
        all_hits.update(element.hits)

    info("Covered %d basic blocks in total using %d files" % (len(all_hits), len(filtered_coverage_set)))
    info("  Number of shared basic locks %d" % (len(shared_hits)))

if __name__ == "__main__":
    main()