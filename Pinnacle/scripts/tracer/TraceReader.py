'''
Created on May 29, 2011

@author: agustin
'''

import idc
import idaapi

from logging import info, debug

class InvalidTraceFileException(Exception):
    pass

TL_IMG_LOAD = "1"
TL_INST_EXEC = "2"
TL_JMP_RESOLVE = "3"
TL_BBLOCK_HIT = "4"
TL_ASSERT = "5"
    
class Trace(object):
    def __init__(self, address):
        self.address = address
        
    def __eq__(self, other):
        return self.address == other.address
    
    def __hash__(self):
        return self.address


class AssertionTrace(Trace):
    def __init__(self, values):
        Trace.__init__(self, int(values[0], 16))

    def __str__(self):
        return "[AssertionTrace: address=%x]" % self.address


class JumpResolveTrace(Trace):
    def __init__(self, values):
        Trace.__init__(self, int(values[0]))
        self.resolved = int(values[1], 16)

    def __str__(self):
        return "[JumpResolveTrace: address=%x]" % self.address

        
class LibraryLoadTrace(Trace):
    def __init__(self, values):        
        self.name = values[0]
        self.low_address = int(values[1], 16)
        self.hi_address = int(values[2], 16)

        Trace.__init__(self, self.low_address)

    def __str__(self):
        return "[LibraryLoadTrace: name=%s, lo_address=%x, hi_address=%x]" % \
            (self.name, self.low_address, self.hi_address)

class BasicBlockHitTrace(Trace):
    def __init__(self, values):
        Trace.__init__(self, int(values[0], 16))
        
    def __str__(self):
        return "[BasicBlockHitTrace: address=%x]" % self.address

class TaintedInstructionTrace(Trace):
    def __init__(self, values):
        Trace.__init__(self, int(values[0], 16))
        
    def __str__(self):
        return "[TaintedInstructionTrace: address=%x]" % self.address

class TraceReader(object):
    '''
    TraceReader
    '''

    def __init__(self, filename):
        '''
        TraceReader
        '''
        self.bbhit_trace = set()
        self.ins_trace = set()
        self.lib_trace = set()
        self.res_trace = set()
        self.assertion_trace = set()
        
        try:
            self.fd = open(filename, "rb")
        except IOError, e:
            raise InvalidTraceFileException(e)
        
        i = 0
        
        # Inefficient as fuck.
        for line in self.fd.readlines():
            if not i % 20000:
                info("Reading line %d" % i)
            
            i += 1
            
            values = line.strip('\n').split(',')
            
            if values[0] == TL_IMG_LOAD:
                self.lib_trace.add(LibraryLoadTrace(values[1:]))
            elif values[0] == TL_INST_EXEC:
                self.ins_trace.add(TaintedInstructionTrace(values[1:]))
            elif values[0] == TL_JMP_RESOLVE:
                self.res_trace.add(JumpResolveTrace(values[1:]))
            elif values[0] == TL_BBLOCK_HIT:
                self.bbhit_trace.add(BasicBlockHitTrace(values[1:]))
            elif values[0] == TL_ASSERT:
                self.assertion_trace.add(AssertionTrace(values[1:]))

class ColorMarker(object):
    def __init__(self, ins_trace, color):
        self.color = color
        self.ins_trace = ins_trace
        
    def mark(self):
        for ins in self.ins_trace:
            idc.SetColor(ins.address, idc.CIC_ITEM, self.color)
             
class AssertionMarker(ColorMarker):
    """
    Mark taint assertions as light red
    """
    def __init__(self, ins_trace):
        ColorMarker.__init__(self, ins_trace, 0xF78181)
                   
class TaintedMarker(ColorMarker):
    """
    Mark tainted instructions as light blue
    """
    def __init__(self, ins_trace):
        ColorMarker.__init__(self, ins_trace, 0xA6D5F9)

class BasicBlockMarker(ColorMarker):
    """
    Mark executed basic blocks as light green
    """
    def __init__(self, ins_trace):
        ColorMarker.__init__(self, ins_trace, 0xBDFC92)
                
    def mark_ea(self, ea):
        idc.SetColor(ea, idc.CIC_ITEM, self.color)

    def handle_block(self, ea):
        curr = ea
        
        done = False
        while curr != idaapi.BADADDR:
            if curr != ea:
                xb = idaapi.xrefblk_t()
                ok = xb.first_to(curr, idaapi.XREF_ALL)
                while ok and xb.iscode:
                    if xb.type in [idaapi.fl_JF, idaapi.fl_JN]:
                        done = True
                        break
                    ok = xb.next_to()
        
            if done:
                break
            
            self.mark_ea(curr)
        
            next = idaapi.BADADDR
            xb = idaapi.xrefblk_t()
            ok = xb.first_from(curr, idaapi.XREF_ALL)
            while ok and xb.iscode:
                if xb.type in [idaapi.fl_JF, idaapi.fl_JN]:
                    done = True
                    break
                elif xb.type == idaapi.fl_F:
                    next = xb.to
                
                ok = xb.next_from()
            
            if done:
                break
            
            curr = next
            
    def mark(self):
        for ins in self.ins_trace:
            self.handle_block(ins.address)