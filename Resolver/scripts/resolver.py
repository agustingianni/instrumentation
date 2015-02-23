import os
import json

class AddressResolver:
    def __init__(self, loaded_images):
        self.loaded_images = loaded_images
        self.last_image = None
        
    def get_offset(self, address):
        return address - self.get_image(address).lo_addr

    def get_image(self, address):
        # Do a bit of caching
        if self.last_image and self.last_image.contains(address):
            return self.last_image
        
        # if it was not cached, traverse all of the loaded images
        for image in self.loaded_images:
            if image.contains(address):
                self.last_image = image
                return image
            
        return None
    
    def rebase(self, address, new_base):
        return new_base + self.get_offset(address)

class LoadedImage:
    def __init__(self, name, lo_addr, hi_addr):
        self.name = name
        self.lo_addr = lo_addr
        self.hi_addr = hi_addr

    def contains(self, address):
        return (address >= self.lo_addr and address < self.hi_addr)
    

import idautils
import idaapi
import idc

def import_branches(data_json, resolver):
    image_functions = set(idautils.Functions())
    image_base = idaapi.get_imagebase()

    n_new_functions = 0
    n_new_xrefs = 0
    
    for element in data_json["indirect_branches"]:
        # Rebase all the addresses.
        call_addr = resolver.rebase(element["from"], image_base)
        refs = map(lambda x: resolver.rebase(x, image_base), element["to"])
        
        # If not present in ida's function list, add it.
        if not call_addr in image_functions:
            # assert idc.MakeCode(call_addr) != 0
            # assert idc.MakeFunction(call_addr) != 0
            # image_functions.add(call_addr)
            # print "Creating function @ %.16x" % call_addr
            n_new_functions += 1
        
        # Get the references
        function_xrefs = [x.frm for x in idautils.XrefsTo(call_addr, 0)]
        
        # Add the references if missing.      
        for ref in refs:
            if not ref in function_xrefs:
                print "Creating XREF from %.16x to %.16x" % (call_addr, ref)
                
                # Make code just in case.
                idc.MakeCode(call_addr)
                idc.MakeCode(ref)
                
                idc.AddCodeXref(call_addr, ref, idc.XREF_USER | idc.fl_CN)
                n_new_xrefs += 1

    for element in data_json["direct_branches"]:
        # Rebase all the addresses.
        func_addr = resolver.rebase(element["function"], image_base)
        refs = map(lambda x: resolver.rebase(x, image_base), element["references"])
        
        # If not present in ida's function list, add it.
        if not func_addr in image_functions:
            # assert idc.MakeCode(func_addr) != 0
            # assert idc.MakeFunction(func_addr) != 0
            # image_functions.add(func_addr)
            print "Creating function @ %.16x" % func_addr
            n_new_functions += 1
        
        # Get the references
        function_xrefs = [x.frm for x in idautils.XrefsTo(func_addr, 0)]
        
        # Add the references if missing.      
        for ref in refs:
            if not ref in function_xrefs:
                print "Creating XREF from %.16x to %.16x" % (ref, func_addr)
                # idc.AddCodeXref(ref, func_addr, idc.XREF_USER | idc.fl_CN)
                n_new_xrefs += 1

    print "Created %d new functions" % n_new_functions
    print "Created %d new xrefs" % n_new_xrefs

def get_loaded_images_information(data_json):
    loaded_images = []
    for image in data_json["loaded_images"]:
        loaded_images.append(LoadedImage(image["name"], image["lo_addr"], image["hi_addr"]))
        
    return loaded_images

input_file = os.path.abspath("../Resolver/clang.json")
print "Using file %s" % input_file

# Load the json in memory.
data_json = json.load(open(input_file))

# Load the image information, needed to un-aslr the addresses.
loaded_images = get_loaded_images_information(data_json)
resolver = AddressResolver(loaded_images)

# Mark all the branches.
import_branches(data_json, resolver)
