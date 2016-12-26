'''
Created on Mar 17, 2012

@author: gr00vy
'''
import idc
import sys
import os

if os.path.abspath('../scripts') not in sys.path:
    sys.path.append(os.path.abspath('../scripts'))

from idaapi import Choose2, fl_CN
from helpers.AddressResolver import AddressResolver
from trace_.TraceReader import TraceReader
from idc import add_dref, dr_R, AddCodeXref
from idautils import XrefsTo
from helpers.Utilities import GetAddressName
import idaapi
import idc

class ResolvedIndirectBranchExporter:
    def __init__(self):
        pass
    
    def export(self, resolved_branches):
        dict_ = {}
        for r in resolved_branches:
            dict_.setdefault(r[0], set()).add(r[1])

        for key, val in dict_.iteritems():            
            prev_comment = idc.GetCommentEx(key, False)
            
            if not prev_comment or "Resolved:" in prev_comment:
                prev_comment = "Resolved:\n"
                 
            for v in val:
                prev_comment += "%s : %.8x\n" % (GetAddressName(v), v)
                            
                # Check if we already have a cross reference
                if key in [ref.frm for ref in XrefsTo(v, 0)]:
                    continue
                
                if AddCodeXref(key, v, fl_CN) != True:
                    idaapi.msg("Could not create cross reference from %x to %x\n" %(key, v))
            
            idc.MakeComm(key, prev_comment)
                    
class BasicBlockHitExporter:
    """
    This will export all the basic block hits from the trace into IDA.
    It will mark hit function in a light color to diferentiate them from
    the non hit ones. Also each basic block will be colored with a greeneish
    color to make evident that the basic block was hit.
    """
    def __init__(self):
        self.MARKED_INS_COLOR = 0x9CFF9D
        self.MARKED_FUNC_COLOR = 0xF6FFF0
        
    def __set_function_color__(self, ea):
        idc.SetColor(ea, idc.CIC_FUNC, self.MARKED_FUNC_COLOR)
        
    def __set_instruction_color__(self, ea):
        idc.SetColor(ea, idc.CIC_ITEM, self.MARKED_INS_COLOR)
        
    def __handle_block__(self, ea):
        curr = ea
        func = idaapi.get_func(ea)
        
        # Mark the complete function with one color
        if func is not None:
            self.__set_function_color__(func.startEA)
        
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
            
            self.__set_instruction_color__(curr)
            
            next_ = idaapi.BADADDR
            xb = idaapi.xrefblk_t()
            ok = xb.first_from(curr, idaapi.XREF_ALL)
            while ok and xb.iscode:
                if xb.type in [idaapi.fl_JF, idaapi.fl_JN]:
                    done = True
                    break
                elif xb.type == idaapi.fl_F:
                    next_ = xb.to
                ok = xb.next_from()
            
            if done:
                break
            
            curr = next_  

    def export(self, hits):
        for ea in hits:
            self.__handle_block__(ea)

class InterestingFunctionExporter:
    """
    This will export all the basic block hits from the trace into IDA.
    It will mark hit function in a light color to diferentiate them from
    the non hit ones. Also each basic block will be colored with a greeneish
    color to make evident that the basic block was hit.
    """
    def __init__(self):
        self.MARKED_FUNC_COLOR = 0xFFCAEF
        
    def __set_function_color__(self, ea):
        idc.SetColor(ea, idc.CIC_FUNC, self.MARKED_FUNC_COLOR)

    def export(self, interesting_functions):
        for ea in interesting_functions:
            func = idaapi.get_func(ea)
            
            # Mark the complete function with one color
            if func is not None:
                self.__set_function_color__(func.startEA)

class VTableIDAExporter:
    def export(self, vtables):
        """
        @vtables: List of tuples with vtable information
                  [(ins_addr, vtable), ... ]
                  
        There is a small mistake. Some .data references will be tagged as being 
        vtables. This is due to the way we detect them on pin. In IDA pro it should
        be easy to mark just only the ones that refer to .text but I could not find
        a way to get that information from idapython.
        """
        
        # We build a dictionary with the ins addr referencing the vtable as the key
        dict_ = {}
        for vtable in vtables:
            # Add all the vtable references found while tracing to the set
            dict_.setdefault(vtable[0], set()).add(vtable[1])
            
        for (key, val) in dict_.iteritems():
            prev_comment = idc.GetCommentEx(vtable[0], False)
            
            # Check if we already have commented this line. This will avoid duplicating info.
            if not prev_comment or "VTables found:" in prev_comment:
                prev_comment = "VTables found:\n"
                
            prev_comment += "\n".join(map(lambda x: "0x%.8x" % x, val))
                                
            # vtable[0] == instruction address
            idc.MakeComm(key, prev_comment)

            # Check if we already have a cross reference
            for v in val:
                if key in [ref.frm for ref in XrefsTo(v, 0)]:
                    continue
                            
                # Add a data reference 
                if add_dref(key, v, dr_R) != True:
                    idaapi.msg("Could not create cross reference from %x to %x\n" %(key, v))

def main():
    #filename = idaapi.askfile_c(0, "pintool.log", "Trace file to load.")
    filename = "C:\Users\gr00vy\Desktop\AssortedShit\Recoverer\pintool.log"
    if filename is None:
        idaapi.msg("Aborting ...\n")

    # Get loaded binary name
    image_name = idc.GetInputFile()
    idaapi.msg("Binary name %s\n" % image_name)
        
    # Get the image base
    image_base = idaapi.get_imagebase()
    idaapi.msg("Binary base 0x%.8x\n" % image_base)

    analyzer = TraceReader(filename)
    analyzer.parse()
    
    resolver = AddressResolver(analyzer.getLoadedImages())    

    # --------------------------------------------------------------------------------------------------------------

    vtables = []
    # Get all the memory accesses
    for x in analyzer.getMemoryWrites():
        ins_addr = resolver.getAddress(x.ins_addr, image_base, image_name)
        
        # Second element of the tuple indicates that it could resolve the address.
        if ins_addr[1] == True:
            vtable_addr = ((1 << (x.write_size*8))-1) & x.content
            if resolver.isValidAddress(vtable_addr):
                vtable_addr = resolver.getAddress(vtable_addr, image_base, image_name)[0]
                vtables.append((ins_addr[0], vtable_addr))                
    
    exporter = VTableIDAExporter()
    exporter.export(vtables)
    
    # --------------------------------------------------------------------------------------------------------------
    
    hits = map(lambda x: resolver.getAddress(x.address, image_base, image_name)[0], analyzer.getBasicBlockHits())
    exporter = BasicBlockHitExporter()
    exporter.export(hits)

    # --------------------------------------------------------------------------------------------------------------

    resolved_branches = []
    # get a list of all the resolved branches
    for x in analyzer.getResolvedBranches():
        ins_addr = resolver.getAddress(x.ins_addr, image_base, image_name)
        branch_addr = resolver.getAddress(x.branch_addr, image_base, image_name)
        
        if ins_addr[1] and branch_addr[1]:
            resolved_branches.append((ins_addr[0], branch_addr[0]))

    exporter = ResolvedIndirectBranchExporter()
    exporter.export(resolved_branches)
    
    interesting_functions = map(lambda x: x.ins_addr, analyzer.getFunctions())
    exporter = InterestingFunctionExporter()
    exporter.export(interesting_functions)
    
    # --------------------------------------------------------------------------------------------------------------
    
if __name__ == "__main__":
    main()