'''
This script will read a trace file create by Recoverer and
create a table of the potentially interesting functions.

Also it will add a comment at the begining of the function
with the size of the object passed to the interesting function.

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

class InterestingFunctionsDialog(Choose2):
    def __init__(self, functions):
        Choose2.__init__(self, "Interesting function", [ ["Function Address", 16], ["Function Name", 32]])
        self.n = 0
        
        self.items = []
        for ins_addr in functions:
            self.items += [self.make_item(ins_addr)]
        
        self.icon = 0
        self.selcount = 0
        self.deflt = -1
        self.popup_names = ["NOSE"]

    def OnClose(self):
        pass

    def OnEditLine(self, n):
        print self.items[n]
        #idaapi.jumpto(int(self.items[n], 16))

    def OnInsertLine(self):
        pass

    def OnSelectLine(self, n):
        self.selcount += 1
        print self.items[n]
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

    def make_item(self, function_address):
        r = ["0x%08x" % function_address, GetAddressName(function_address)]
        self.n += 1
        return r

    def OnGetLineAttr(self, n):
        #if n % 2:
        #    return [0xF00000, 0]
        pass    

def main():
    filename = idaapi.askfile_c(0, "pintool.log", "Trace file to load.")
    #filename = RECOVERER_PATH + "\\calc_trace.sample"
    if filename is None:
        idaapi.msg("Aborting ...\n")

    # Get loaded binary name
    image_name = idc.GetInputFile()
    idaapi.msg("Binary name %s\n" % image_name)
        
    # Get the image base
    image_base = idaapi.get_imagebase()
    idaapi.msg("Binary base 0x%.8x\n" % image_base)

    analyzer = TraceReader(filename)
    analyzer.parse(match_events="LIAXF")

    resolver = AddressResolver(analyzer.getLoadedImages())
    
    resolved = []
    
    for x in analyzer.getFunctions():
        ins_addr = resolver.getAddress(x.ins_addr, image_base, image_name)

        # Second element of the tuple indicates that it could resolve the address.
        if ins_addr[1] == True:
            resolved.append(ins_addr[0])
        else:
            continue
        
        collected = set()
        for use in x.chunks_used:
            collected.add((use.chunk.chunk_size, use.offset))

        for use in collected:
            comment = "ecx {sz=%x, off=%x}" % use
            idc.MakeComm(ins_addr[0], comment)

    rb_dialog = InterestingFunctionsDialog(resolved)
    rb_dialog.show()
    
if __name__ == "__main__":
    main()