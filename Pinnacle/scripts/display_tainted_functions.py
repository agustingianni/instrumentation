"""
Imports a hit-trace file and displays a list of functions that process
tainted data. Clicking on a function in the list then colors all
instructions in that function that operate on tainted data.

@author: sean@heelan.ie
"""

import sys
import os

import idc
import idaapi

import utils
from imgfileparser import ImageFileParser

TAINTED = 0xffff00
FUNC_MARKER = "T_"            
        
class TaintedFunctionsDialog(idaapi.Choose2):
    def __init__(self, functions, function_to_addrs):
        """
        @type functions: List of Tuple of (Int, String)
        @param functions: A list of function entry points and names

        @type function_to_addrs: Dict of Int -> List of Int
        @param function_to_addrs: A map from function entry points to a list
            of tainted instruction addresses within that function
        """
        
        Choose2.__init__(self, "Tainted Functions", [ ["Address", 16],
                                                      ["Name", 16],
                                                      ["# Tainted Instrs"]])

        self.function_to_addrs = function_to_addrs
        
        self.n = 0

        self.items = []
        for addr, name in functions:
            self.items += [self.make_item(addr, name, len(function_to_addrs[addr]))]
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
        func_addr = int(self.items[n][0], 16)
        func_name = self.items[n][1]

        t_addrs = self.function_to_addrs[func_addr]
        idaapi.msg("%d tainted instructions in %s\n" % \
                       (len(t_addrs), func_name))

        for tainted_addr in t_addrs:
            idaapi.set_item_color(tainted_addr, TAINTED)

        idaapi.jumpto(func_addr)

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
        return 2

    def show(self):
        t = self.Show()
        if t < 0:
            return False
        return True

    def make_item(self, addr, name, t_instr_cnt):
        r = ["0x%08x" % addr, name, "%.8d" % t_instr_cnt]
        self.n += 1
        return r

    def OnGetLineAttr(self, n):
        pass    

def main():
    input_dir = utils.ask_for_input_dir()

    img_path = os.path.join(input_dir, utils.IMG_LOAD_FNAME)
    if not os.access(img_path, os.R_OK):
        idaapi.msg("Cannot access %s. Does it exist?" % img_path)
        return -1
        
    img_file_parser = ImageFileParser(img_path)    
    
    hit_path = os.path.join(input_dir, utils.INSTR_HIT_FNAME)
    if not os.access(img_path, os.R_OK):
        idaapi.msg("Cannot access %s. Does it exist?" % hit_path)
        return -1    

    prefix_funcs = False
    if idc.AskYN(0, "Prefix tainted functions with %s?" % FUNC_MARKER) == 1:
        prefix_funcs = True

    color_now = False
    if idc.AskYN(0, "Color all tainted instructions now?") == 1:
        color_now = True
        
    hit_rvas = set()
    x = idc.GetInputFile().lower()
    logged_not_found = set()
    with open(hit_path, 'r') as fd:
        for line in fd:
            split_line = line.strip().split(";")
            img_load_id = int(split_line[1], 16)
            addr = int(split_line[2], 16)

            # Check if the instruction was in the current image
            instr_img = img_file_parser.get_addr_img(addr, img_load_id)
            if instr_img is None:
                if addr not in logged_not_found:
                    idaapi.msg("Could not find image for address " + \
                               " 0x%x at image load id 0x%x\n" % \
                               (addr, img_load_id))
                    logged_not_found.add(addr)
                continue
            
            y = os.path.basename(instr_img.img_path).lower()
            if x != y:
                continue

            rva = addr - instr_img.low_addr
            hit_rvas.add(rva)

    idaapi.msg("%d tainted instructions in the current module\n" % \
               len(hit_rvas))
    
    function_to_addrs = {}
    curr_base = idaapi.get_imagebase()
    # Reduce the instruction hit trace to a set of functions
    for rva in hit_rvas:
        instr = rva + curr_base
        if color_now:
            idaapi.set_item_color(instr, TAINTED)
            
        func = idaapi.get_func(instr)
        if func is None:
            continue

        # We also store each unique instruction address per
        # function so we can later highlight them
        if func.startEA in function_to_addrs:
            function_to_addrs[func.startEA].append(instr)
        else:
            function_to_addrs[func.startEA] = [instr]

    functions = []
    tmp = list(function_to_addrs.keys())
    tmp.sort()
    for ea in tmp:
        curr_name = idaapi.get_func_name(ea)
        if prefix_funcs and not curr_name.startswith(FUNC_MARKER):
            # Add some marker to the start of the function name
            # so we know which ones process tainted data
            idaapi.set_name(ea, FUNC_MARKER + curr_name)
        functions.append((ea, idaapi.get_func_name(ea)))

    idaapi.msg("%d functions process tainted data\n" % len(functions))
    dialog = TaintedFunctionsDialog(functions, function_to_addrs)
    dialog.show()
    
if __name__ == "__main__":
    main()
