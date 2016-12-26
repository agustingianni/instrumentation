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
from trace_.TraceReader import TraceReader
from helpers.Utilities import GetAddressName
from idc import GetDisasm

class VTablesDialog(Choose2):
    def __init__(self, writes):
        Choose2.__init__(self, "VTable writes", [ ["Address", 16], ["VTable addresses", 16], ["Instruction", 16]])
        self.n = 0
        
        write_map = {}

        self.items = []
        for value in writes:
            write_map.setdefault(value[0], set()).add(value[1])

        for (key, val) in write_map.iteritems():
            self.items += [self.make_item((key, val))]
        
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

    def make_item(self, value):
        #[["Address", 16], ["VTable addresses", 16], ["Name", 16], ["Instruction", 16]]
        tmp = " | ".join(map(lambda x: "0x%.8x" % x, value[1]))
        r = ["0x%.8x" % value[0], tmp, GetDisasm(value[0]).split(";")[0]]
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
    image_name = idc.GetInputFile()
    idaapi.msg("Binary name %s\n" % image_name)
        
    # Get the image base
    image_base = idaapi.get_imagebase()
    idaapi.msg("Binary base 0x%.8x\n" % image_base)

    analyzer = TraceReader(filename)
    analyzer.parse()
    
    resolver = AddressResolver(analyzer.getLoadedImages())
    
    vtables = []
    
    # Get all the memory accesses
    for x in analyzer.getMemoryWrites():
        ins_addr = resolver.getAddress(x.ins_addr, image_base, image_name)
        
        # Second element of the tuple indicates that it could resolve the address.
        if ins_addr[1] == True:
            vtable_addr = ((1 << (x.write_size*8))-1) & x.content
            if resolver.isValidAddress(vtable_addr):
                vtables.append((ins_addr[0], vtable_addr))
            
    rb_dialog = VTablesDialog(vtables)
    rb_dialog.show()
    
if __name__ == "__main__":
    main()