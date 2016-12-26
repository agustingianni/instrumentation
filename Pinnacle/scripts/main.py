'''
Created on Jun 4, 2011

@author: gr00vy
'''
import os
import sys

from logging import info, basicConfig, DEBUG
from tracer.TraceReader import InvalidTraceFileException, BasicBlockMarker,\
    TaintedMarker, AssertionMarker

basicConfig(format='[%(levelname)s] : %(message)s', level=DEBUG)

try:
    from pintool.PinnaclePintool import PinnaclePintool
    from tracer.TraceReader import TraceReader
    import idc
except ImportError, e:
    print "Failed importing some of the needed modules. Please install whatever is missing"
    print "Exception : %s " % e

    sys.exit()

def main():
    info("Running pintool")
    
    # OPEN = 0, SAVE = 1
    #filename = idc.AskFile(0, "*", "Choose a file to run under pintool")     
    #arguments = idc.AskStr("", "Specify command line arguments for %s" % os.path.basename(filename))
 
    #info("Got filename %s" % filename)
    #info("Got arguments %s" % arguments)
        
    try:
        #tool = PinnaclePintool()
        trace_log = idc.AskFile(0, "*", "Choose a file to run under pintool")
        if not os.path.exists(trace_log):  
            tool.run(filename + arguments)
         
        tr = TraceReader(trace_log)
        
        m = BasicBlockMarker(tr.bbhit_trace)
        m.mark()
        
        m = TaintedMarker(tr.ins_trace)
        m.mark()

        m = AssertionMarker(tr.assertion_trace)
        m.mark()
        
    except InvalidTraceFileException, e:
        info("Could not find trace file")
        return -1
        
if __name__ == '__main__':
    main()