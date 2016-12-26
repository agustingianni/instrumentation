"""
This tool runs our code coverage pintool over a set of files inside a
directory.
"""
import os
import subprocess

from multiprocessing import Pool

INPUT_FILES  = "/Users/anon/images/ttf"
PINTOOL      = "/Users/anon/workspace/instrumentation/CodeCoverage/obj-intel64/CodeCoverage.dylib"
BINARY_NAME  = "/Users/anon/Desktop/Reversing/inspect"

def process_files(f):
    print "%d -> Getting code coverage for file '%s'" % (os.getpid(), f)
    file_name = os.path.join(INPUT_FILES, f)
    trace_name = file_name + ".trace"
    subprocess.call(["pin", "-t", PINTOOL, "-l", trace_name, "--", BINARY_NAME, file_name], stdout=open(os.devnull, "w"), stderr=subprocess.STDOUT)

if __name__ == "__main__":
    input_files = filter(lambda x: x[0] != ".", os.listdir(INPUT_FILES))

    try:
        # Create several workers.
        proc_pool = Pool(10)
        proc_pool.map(process_files, input_files)

    except KeyboardInterrupt, e:
        print "Caught KeyboardInterrupt, terminating workers"
        proc_pool.terminate()
        proc_pool.join()