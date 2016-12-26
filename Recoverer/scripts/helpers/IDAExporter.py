'''
Created on May 26, 2012

@author: gr00vy
'''

import os
import sys
from logging import info, basicConfig, INFO

basicConfig(format='[%(levelname)s] : %(message)s', level=INFO)

if os.environ.has_key("RECOVERER_PATH"):
    RECOVERER_PATH = os.environ["RECOVERER_PATH"]
    if os.path.abspath(RECOVERER_PATH + "scripts") not in sys.path:
        sys.path.append(os.path.abspath(RECOVERER_PATH + "\\scripts"))
else:
    raise Exception("RECOVERER_PATH environment variable not set, go set it")

try:
    from idautils import Functions
    from idaapi import get_func
    import idc
    import idaapi
except ImportError:
    pass

from helpers.Utilities import GetAddressName
from sa.codegraph import guess_calling_conv, CCONV_INVALID
from collections import namedtuple

class IDADatabaseExporter:
    """
    Simple exporter of the IDA Pro database. So far it just
    exports the image base and function information such as
    function rva, function name (if any).
    
    This is supposed to be used from IDA Pro as an independent 
    script.
    """
    def __init__(self):
        self.image_base = 0
        
    def export(self):
        image_name = idc.GetInputFile()
        self.image_base = idaapi.get_imagebase()
        
        self.filename = "%s.db" % (image_name)
        
        datadir = os.path.join(RECOVERER_PATH, "data")
        if not os.path.exists(datadir):
            os.mkdir(datadir)
        
        self.filename = os.path.join(datadir, self.filename)
        
        if os.path.exists(self.filename):
            info("File %s exists, overwriting." % (self.filename))
        else:
            info("Creating database at %s." % (self.filename))
        
        self.fd = open(self.filename, "w")

        self.fd.write("IMAGE_BASE;0x%x\n" % (self.image_base))
        self.fd.write("IMAGE_NAME;%s\n"   % (image_name))
        self.__export_functions__()
        self.__export_imports__()
        
        self.fd.close()
    
    def __export_imports__(self):
        imports = []    
        def imp_cb(ea, name, ord):
            if name:
                imports.append(ea)
    
            # True -> Continue enumeration
            # False -> Stop enumeration
            return True
        
        nimps = idaapi.get_import_module_qty()
            
        for i in xrange(0, nimps):
            name = idaapi.get_import_module_name(i)
            if not name:
                continue
        
            idaapi.enum_import_names(i, imp_cb)
        
        for imp in imports:
            self.fd.write("I;0x%x;%s\n" % (imp - self.image_base, GetAddressName(imp)))
    
    def __export_functions__(self):
        # Loop from start to end in the current segment
        for funcea in Functions():
            func = get_func(funcea)
            
            cconv = guess_calling_conv(func)
            if cconv == CCONV_INVALID:
                print "Skiping function 0x%.8x, it has no clear start basic block" % func.startEA
                continue

            self.fd.write("F;0x%x;0x%x;0x%x;%s\n" % (func.startEA - self.image_base,
                                                     func.endEA - self.image_base,
                                                     cconv, 
                                                     GetAddressName(func.startEA)))
            
            # Export all the basic blocks
            for block in idaapi.FlowChart(func):
                self.fd.write("B;0x%x;0x%x;0x%x;0x%x\n" % (func.startEA - self.image_base, 
                    block.startEA - self.image_base, block.endEA - self.image_base, block.id))

Import     = namedtuple("Import"    , ["start", "name"])
Function   = namedtuple("Function"  , ["start", "end", "cconv", "name"])
BasicBlock = namedtuple("BasicBlock", ["function", "start", "end", "id"])

class IDADatabase:
    """
    This simple class loads the exported IDA Pro database. 
    """
    def __init__(self, image_name):
        datadir = os.path.join(RECOVERER_PATH, "data")
        if not os.path.exists(datadir):
            os.mkdir(datadir)
        
        self.filename = "%s.db" % (image_name)
        self.filename = os.path.join(datadir, self.filename)
        
        if not os.path.exists(self.filename):
            info("Database at %s does not exist. Did you export the database from IDA Pro?." % (self.filename))

        self.db = {}
    
    def get_function_basic_blocks(self, rva):
        return filter(lambda x: x.function == rva, self.db["basic_blocks"])

    def get_function_by_rva(self, rva):
        bb = self.get_basic_block_from_rva(rva)
        if not bb:
            return None
        
        return self.get_function(bb.function)

    def get_basic_block_from_rva(self, rva):
        for bb in self.get_basic_blocks():
            if rva >= bb.start and rva < bb.end:
                return bb
            
        return None

    def get_basic_blocks(self):
        return self.db["basic_blocks"]
    
    def get_function(self, rva):
        """
        This is used only when we are sure that RVA is exactly the address
        of the function, otherwise it will fail.
        
        Use get_function_by_rva if unsure.
        """
        for f in self.db["functions"].values():
            if f.start == rva:
                return f

        return None
        
    def get_functions(self):
        return self.db["functions"].values()
    
    def get_imports(self):
        return self.db["imports"].values()
    
    def get_import_name(self, rva):
        return self.db["imports"][rva].name

    def get_function_name(self, rva):
        return self.db["functions"][rva].name
    
    def get_address_name(self, rva):
        if self.db["imports"].has_key(rva):
            return self.get_import_name(rva)
        
        if self.db["functions"].has_key(rva):
            return self.get_function_name(rva)
        
        return "InvalidName"
    
    def get_image_base(self):
        return self.db["image_base"]
    
    def load(self):
        info("Loading IDA Pro database from %s." % (self.filename))
        
        self.fd = open(self.filename, "r")
        
        for line in self.fd:
            tokens = line.strip().split(";")
            
            if tokens[0] == "F":
                start_ea, end_ea = map(lambda x: int(x, 16), tokens[1:3])
                cconv = int(tokens[3], 16)
                name = tokens[4]
                self.db.setdefault("functions", {})[start_ea] = Function(start_ea, end_ea, cconv, name)
                
            elif tokens[0] == "B":
                function, start_ea, end_ea, bb_id = map(lambda x: int(x, 16), tokens[1:5])
                self.db.setdefault("basic_blocks", []).append(BasicBlock(function, start_ea, end_ea, bb_id))
                
            elif tokens[0] == "IMAGE_BASE":
                self.db["image_base"] = int(tokens[1], 16)
                
            elif tokens[0] == "IMAGE_NAME":
                self.db["image_name"] = tokens[1]
                
            elif tokens[0] == "I":
                start_ea = int(tokens[1], 16)
                name = tokens[2]
                self.db.setdefault("imports", {})[start_ea] = Import(start_ea, name)
                
            else:
                raise Exception("Invalid log entry.")
            
        self.fd.close()
        
        info("Finished loading IDA Pro database.")

if __name__ == '__main__':
    exporter = IDADatabaseExporter()
    exporter.export()
    
    info("Finished exporting database.")
    
    """
    # Testing the database.
    
    ida_db = IDADatabase("mshtml.dll")
    ida_db.load()
    
    for function in ida_db.db["functions"]:
        print function
    """