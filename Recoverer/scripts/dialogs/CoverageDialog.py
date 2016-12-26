'''
Created on Mar 10, 2012

@author: gr00vy
'''
import sys
import os

if os.environ.has_key("RECOVERER_PATH"):
    RECOVERER_PATH = os.environ["RECOVERER_PATH"]
    if os.path.abspath(RECOVERER_PATH + "scripts") not in sys.path:
        sys.path.append(os.path.abspath(RECOVERER_PATH + "\\scripts"))
else:
    raise Exception("RECOVERER_PATH environment variable not set, go set it")
    
from idaapi import Choose2
from helpers.AddressResolver import AddressResolver
from helpers.Utilities import GetAddressName
from trace_.TraceReader import TraceReader

# IDA Colors are fucked up no idea why?
MARKED_INS_COLOR  = 0xCAFECA    # Kind of green will be the color of reached basic block.
MARKED_FUNC_COLOR = 0xF9F7FF    # pink will be the color of the whole function

def SetFunctionColor(ea):
    idc.SetColor(ea, idc.CIC_FUNC, MARKED_FUNC_COLOR)

def SetInstructionColor(ea):
    idc.SetColor(ea, idc.CIC_ITEM, MARKED_INS_COLOR)
    
def SetBasicBlockColor(ea):
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

        SetInstructionColor(curr)
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

class ReachedFunctionsDialog(Choose2):
    def __init__(self, reached_functions):
        Choose2.__init__(self, "Functions reached", [ ["Address", 16], ["Name", 16]])
        self.n = 0
        
        self.items = []
        for value in reached_functions:
            self.items += [self.make_item(value, GetAddressName(value))]
        
        self.icon = 0
        self.selcount = 0
        self.deflt = -1
        self.popup_names = ["NOSE"]

    def OnClose(self):
        pass

    def OnEditLine(self, n):
        pass

    def OnInsertLine(self):
        pass

    def OnSelectLine(self, n):
        self.selcount += 1
        idaapi.jumpto(int(self.items[n][0], 16))

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        return n

    def OnDeleteLine(self, n):
        del self.items[n]
        return n

    def OnRefresh(self, n):
        return n

    def OnGetIcon(self, n):
        if n % 2:
            return 10
        
        return 11

    def show(self):
        t = self.Show()
        if t < 0:
            return False
        return True

    def make_item(self, address, name):
        r = ["0x%.8x" % address, name]
        self.n += 1
        return r

    def OnGetLineAttr(self, n):
        #if n % 2:
        #    return [0xF00000, 0]
        pass    

def main():
    filename = idaapi.askfile_c(0, "pintool.log", "Trace file to load.")
    #filename = RECOVERER_PATH + "\\pintool.log"
    if filename is None:
        idaapi.msg("Aborting ...\n")

    # Get loaded binary name
    image_name = idc.GetInputFile().lower()
    idaapi.msg("Binary name %s\n" % image_name)
        
    # Get the image base
    image_base = idaapi.get_imagebase()
    idaapi.msg("Binary base 0x%.8x\n" % image_base)

    analyzer = TraceReader(filename)
    analyzer.parse(match_events="HL")   # This will make things quickier, allow H (basic block hit) and L (library loads)
    
    resolver = AddressResolver(analyzer.getLoadedImages())
    
    hits = []
    reached_functions = set()
    
    # Get all the hits
    for x in analyzer.getBasicBlockHits():
        ins_addr = resolver.getAddress(x.address, image_base, image_name)

        # Second element of the tuple indicates that it could resolve the address.
        if ins_addr[1] == True:
            hits.append(ins_addr[0])
            func = idaapi.get_func(ins_addr[0])
            if func is not None:
                reached_functions.add(func.startEA)

    for hit in hits:
        SetBasicBlockColor(hit)

    for function in reached_functions:
        SetFunctionColor(function)
        
    rb_dialog = ReachedFunctionsDialog(reached_functions)
    rb_dialog.show()
    
if __name__ == "__main__":
    main()