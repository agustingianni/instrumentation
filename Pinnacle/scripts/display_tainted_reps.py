"""
Imports a REP trace file and displays a list of locations where an 
ECX was tainted on an instruction with a REP prefix

@author: sean@heelan.ie
"""

import operator
import sys
import os

import idc
import idaapi

from collections import namedtuple

from pynacle import utils
from pynacle.imgfileparser import ImageFileParser

DisplayRow = namedtuple("DisplayRow", ["func_name", "instr_addr",
                                           "ecx_low", "ecx_high"])
        
class TaintedRepsDialog(idaapi.Choose2):
    def __init__(self, display_data):
        """
        
        """
        
        Choose2.__init__(self, "Tainted REPs", [["Function", 16], 
                                                ["Address", 16],
                                                ["ECX range", 16]])

        self.display_data = display_data        
        self.n = 0

        self.items = []
        for dd in self.display_data:
            self.items += [self.make_item(dd)]
            
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
        addr = int(self.items[n][1], 16)
        idaapi.jumpto(addr)

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

    def make_item(self, d):
        if d.ecx_low == d.ecx_high:
            ecx_str = "0x%x" % low_ecx
        else: 
            ecx_str = "0x%x - 0x%x" % (d.ecx_low, d.ecx_high)
            
        r = [d.func_name, "0x%x" % d.instr_addr, ecx_str]
        
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
    
    reps_path = os.path.join(input_dir, utils.TAINTED_REPS_FNAME)
    if not os.access(reps_path, os.R_OK):
        idaapi.msg("Cannot access %s. Does it exist?" % reps_path)
        return -1    
    
    x = idc.GetInputFile().lower()
    rep_rvas = {}
    logged_not_found = set()
    hit_images = {}
    hit_image_addrs = {}
    with open(reps_path, 'r') as fd:
        for line in fd:
            line = line.strip().split(";")
            addr = int(line[0], 16)
            ecx_val = int(line[1], 16)
            img_load_id = int(line[2], 16)
            
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
                # Keep track of the REPs in other images so 
                # we can log them at the end
                if instr_img.img_path in hit_images:
                    if addr not in hit_image_addrs:
                        hit_images[instr_img.img_path] += 1
                        hit_image_addrs.add(addr)
                else:
                    hit_images[instr_img.img_path] = 1
                    hit_image_addrs = set([addr])
                                    
                continue
            
            rva = addr - instr_img.low_addr
            if rva in rep_rvas:
                rep_rvas[rva].append(ecx_val)
            else:
                rep_rvas[rva] = [ecx_val]
        
    display = []    
    curr_base = idaapi.get_imagebase()    
    for rva, ecx_vals in rep_rvas.items():
        instr = rva + curr_base
        func = idaapi.get_func(instr)
        if func is not None:
            f_name = idaapi.get_func_name(func.startEA)
        else:
            f_name = ""
            
        ecx_vals.sort()
        low = ecx_vals[0]
        high = ecx_vals[-1]
        display.append(DisplayRow(f_name, instr, low, high))
    
    if len(hit_images) > 0:
        idaapi.msg("### Tainted REPs in other images ###\n")
        
        s = sorted(hit_images.iteritems(), key=operator.itemgetter(1))
        for key, val in s:
            idaapi.msg("%d %s\n" % (val, key))    
        
    dialog = TaintedRepsDialog(display)
    dialog.show()
    
if __name__ == "__main__":
    main()
