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


class ResolvedBranchesDialog(Choose2):
    def __init__(self, resolved):
        Choose2.__init__(self, "Resolved Indirect Brances", [ ["Branch Address", 16], ["Target Address", 16], ["Target Name", 32], ["Additional", 32]])
        self.n = 0
        
        self.items = []
        for (ins_addr, branch_addr) in resolved:
            self.items += [self.make_item(ins_addr, branch_addr)]
        
        self.icon = 0
        self.selcount = 0
        self.deflt = -1
        self.popup_names = ["NOSE"]

    def OnClose(self):
        pass

    def OnEditLine(self, n):
        idaapi.jumpto(self.items[n])

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

    def make_item(self, branch_address, branch_target):
        r = ["0x%08x" % branch_address, "0x%08x" % branch_target, GetAddressName(branch_target), GetDisasm(branch_address).split(";")[0]]
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
    analyzer.parse(match_events="XL") # Allow X (resolved branches) and L (load library)
    
    resolver = AddressResolver(analyzer.getLoadedImages())
    
    resolved = []

    # get a list of all the resolved branches 
    for x in analyzer.getResolvedBranches():
        ins_addr = resolver.getAddress(x.ins_addr, image_base, image_name)
        branch_addr = resolver.getAddress(x.branch_addr, image_base, image_name)
        
        # Second element of the tuple indicates that it could resolve the address.
        if ins_addr[1] == True:
            resolved.append((ins_addr[0], branch_addr[0]))
            
    rb_dialog = ResolvedBranchesDialog(resolved)
    rb_dialog.show()
    
    ins2branches = {}
    for (ins_addr, branch_addr) in resolved:
        ins2branches.setdefault(ins_addr, set()).add(branch_addr)
    
    for ins_addr, branches in ins2branches.iteritems():
        comment = "\nResolved branches:\n"
        for branch in branches:
            comment += "%s : %.8x\n" % (GetAddressName(branch), branch)

            # Check if we already have a cross reference
            if ins_addr in [ref.frm for ref in XrefsTo(branch, 0)]:
                continue
            
            if AddCodeXref(ins_addr, branch, fl_CN) != True:
                idaapi.msg("Could not create cross reference from %x to %x\n" %(ins_addr, branch))
            
        idc.MakeComm(ins_addr, comment)
    
    """
    already_commented = set()
    for (ins_addr, branch_addr) in resolved:
        if ins_addr in already_commented:
            prev_comment = idc.GetCommentEx(ins_addr, False)
            idc.MakeComm(ins_addr, "%s%s : %.8x\n" %(prev_comment, GetAddressName(branch_addr), branch_addr))
        else:
            already_commented.add(ins_addr)
            idc.MakeComm(ins_addr, "%s : %.8x\n" % (GetAddressName(branch_addr), branch_addr))

        # Check if we already have a cross reference
        if ins_addr in [ref.frm for ref in XrefsTo(branch_addr, 0)]:
            continue
        
        if AddCodeXref(ins_addr, branch_addr, fl_CN) != True:
            idaapi.msg("Could not create cross reference from %x to %x\n" %(ins_addr, branch_addr))

    """
if __name__ == "__main__":
    main()            