class LoadedModule(object):
    def __init__(self, name, lo_addr, hi_addr):
        self.name = name
        self.lo_addr = lo_addr
        self.hi_addr = hi_addr
        
class TaintedInstruction(object):
    def __init__(self, addr):
        self.addr = addr
        
class TraceReader(object):
    TL_IMG_LOAD = "1"
    TL_IMG_UNLOAD = "2"
    TL_INST_EXEC = "3"
    
    def __init__(self, filename):
        self.filename = filename
        self.cur_modules = []
        self.tainted_ins = []
        self.tainted_modules = {}
    
    def load(self):
        with open(self.filename, "rb") as fd:
            for line in fd:
                if not line:
                    break
                                
                values = line.strip('\n').split(';')
                
                if values[0] == TraceReader.TL_IMG_LOAD:
                    self.cur_modules.append(LoadedModule(values[1], int(values[2]), int(values[3])))
                
                elif values[0] == TraceReader.TL_IMG_UNLOAD:
                    tmp = [x for x in self.cur_modules if x != values[1]]
                    self.cur_modules = tmp

                elif values[0] == TraceReader.TL_INST_EXEC:
                    ins_addr = int(values[1])
                    ins_mod = None
                                        
                    for mod in self.cur_modules:
                        if ins_addr >= mod.lo_addr and ins_addr < mod.hi_addr:
                            ins_mod = mod
                            break 
                        
                    assert ins_mod != None
                    
                    # Get the instruction offset.
                    ins_off = ins_addr - ins_mod.lo_addr
                    self.tainted_modules.setdefault(mod, []).append(ins_off)
                    
import sys                    

if __name__ == '__main__':
    filename = sys.argv[1]
    reader = TraceReader(filename)
    reader.load()
        
    for k, v in reader.tainted_modules.iteritems():
        print k.name, len(v)