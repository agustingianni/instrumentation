'''
Created on Mar 12, 2012

@author: gr00vy
'''
from time import time
import os
import sys

from logging import basicConfig, INFO, debug
basicConfig(format='[%(levelname)s] : %(message)s', level=INFO)

# if os.environ.has_key("RECOVERER_PATH"):
#     RECOVERER_PATH = os.environ["RECOVERER_PATH"]
#     if os.path.abspath(RECOVERER_PATH + "scripts") not in sys.path:
#         sys.path.append(os.path.abspath(RECOVERER_PATH + "\\scripts"))
# else:
#     raise Exception("RECOVERER_PATH environment variable not set, go set it")

def find(f, seq):
    for item in seq:
        if f(item): 
            return item

class BasicBlockHit:
    def __init__(self, address):
        self.address = address
        
    def __repr__(self):
        return "<BasicBlockHit(0x%.8x)>" % self.address 

class Destructor:
    """
    Describes a function that has been identified as a destructor of a class.
    """
    def __init__(self, ins_addr):
        self.ins_addr = ins_addr

    def __repr__(self):
        return "Destructor(0x%.8x)" % self.ins_addr 

    def __eq__(self, rhs):
        if type(rhs) == type(0):
            return self.ins_addr == rhs
        
        return self.ins_addr == rhs.ins_addr

class WriteAccess:
    """
    Memory Write description.
    """
    def __init__(self, ins_addr, chunk_addr, timestamp, write_addr, write_size, content, chunk_ref):
        self.ins_addr   = ins_addr
        self.chunk_addr = chunk_addr
        self.timestamp  = timestamp
        self.write_addr = write_addr
        self.write_size = write_size
        self.content    = content
        
        # This is the timestmap of a chunk that was referenced by this memory write
        self.chunk_ref  = chunk_ref
    
    def __repr__(self):
        return "WriteAccess(ins_addr=0x%.8x, chunk_addr=0x%.8x, timestamp=0x%.8x, write_addr=0x%.8x, write_size=0x%.8x, content=0x%.8x, chunk_ref=0x%.8x)" % \
            (self.ins_addr, self.chunk_addr, self.timestamp, self.write_addr, self.write_size, self.content, self.chunk_ref) 

class ReadAccess:
    """
    Memory Read description.
    """
    def __init__(self, ins_addr, chunk_addr, timestamp, read_addr, read_size, content, chunk_ref):
        self.ins_addr   = ins_addr
        self.chunk_addr = chunk_addr
        self.timestamp  = timestamp
        self.read_size  = read_size
        self.read_addr  = read_addr
        self.content    = content
        self.chunk_ref  = chunk_ref
        
    def __repr__(self):
        return "ReadAccess(ins_addr=0x%.8x, chunk_addr=0x%.8x, timestamp=0x%.8x, read_addr=0x%.8x, read_size=0x%.8x, content=0x%.8x, chunk_ref=0x%.8x)" % \
            (self.ins_addr, self.chunk_addr, self.timestamp, self.read_addr, self.read_size, self.content, self.chunk_ref) 

class LoadedImage:
    """
    Information about a loaded image.
    """    
    def __init__(self, name, lo_addr, hi_addr):
        self.name = name
        self.lo_addr = lo_addr
        self.hi_addr = hi_addr

    def contains(self, address):
        return (address >= self.lo_addr and address < self.hi_addr)
    
    def get_offset(self, address):
        assert address >= self.lo_addr
        assert address < self.hi_addr
        
        return address - self.lo_addr

    def __repr__(self):
        return "LoadedImage(name=%s, lo_addr=0x%.8x, hi_addr=0x%.8x)" % \
            (self.name, self.lo_addr, self.hi_addr) 

class Function:
    """
    Describes a function
    """
    def __init__(self, ins_addr):
        self.ins_addr        = ins_addr
        self.chunks_used     = []
        self.is_valid        = False
        self.accesses_memory = False

    def getChunkUses(self):
        """
        Get a reference to all the chunks that pased through this function call.
        """
        return self.chunks_used

    def __repr__(self):
        return "Function(0x%.8x)" % self.ins_addr 
    
class InterestingFunction:
    """
    An interesting function is an instance of a function
    call that receives as a parameter a pointer to one of our interesting chunks.
    
    Note: The name is misleading, this will eventually change.
    """    
    def __init__(self, ins_addr, chunk, offset):
        self.ins_addr   = ins_addr
        self.offset     = offset
        self.chunk      = chunk
        
    def __repr__(self):
        return "InterestingFunction(ins_addr=0x%.8x, chunk={ %s }, offset=0x%.8x)" % (self.ins_addr, self.chunk, self.offset) 

class InterestingChunk:
    """
    This is the description of a memory chunk. 
    
    Note: the name is misleading, this must change.
    """
    def __init__(self, chunk_addr, chunk_size, timestamp):
        self.chunk_size = chunk_size
        self.chunk_addr = chunk_addr
        self.timestamp  = timestamp
        
        self.offsets    = set()
        
        # Memory accesses
        self.reads      = []
        self.writes     = []
        
        # Later we need to initialize this
        self.type       = None
        self.composite  = None
        
    def getReads(self):
        return self.reads
    
    def getWrites(self):
        return self.writes

    def __repr__(self):
        if self.type:
            name = self.type.name
        else:
            name = "NoType"
            
        return "InterestingChunk(chunk_addr=0x%.8x, chunk_size=0x%.8x, timestamp=0x%.8x, name=%s, composite={ %s })" % \
            (self.chunk_addr, self.chunk_size, self.timestamp, name, self.composite)

class ResolvedIndirectBranch:
    """
    Describes a resolved indirect branch such ass "jmp eax" or "call [mem]" etc.
    """
    def __init__(self, ins_addr, branch_addr):
        self.ins_addr       = ins_addr
        self.branch_addr    = branch_addr

    def __repr__(self):
        return "ResolvedIndirectBranch(ins_addr=0x%.8x, branch_addr=0x%.8x)" % \
            (self.ins_addr, self.branch_addr) 

class TaintedInstruction(object):
    def __init__(self, address):
        self.address = address            

class TraceReader:
    """
    This class will load a trace file and parse it. It will store everything in memory. 
    So far this is ok, but maybe in the future we might need to do something else.
    """
    def __init__(self, filename, size_limit=0):
        """
        @size_limit: the number of megabytes we are going to read from the trace
        file. The default value is zero which means, read all the trace file.
        """
        self.filename = filename
        self.file_size = os.path.getsize(filename)
        self.size_limit = size_limit * 1024 * 1024
        
        # these are the events that we currently load from the trace file
        self.allowed_events = ["L", "W", "R", "I", "A", "X", "F", "D", "H", "T"]
        
        # List of everything we parse from the trace file
        self.images         = []
        self.destructors    = []
        self.functions      = []
        self.writes         = []
        self.reads          = []
        self.chunks         = []
        self.resolves       = []
        self.hits           = []
        self.tainted        = []
        
        # indexes
        self.addr2function  = {}
        self.ts2chunk       = {}        
        self.chunk2function = {}

    def getTaintedInstructions(self):
        return self.tainted

    def getDestructors(self):
        return self.destructors
    
    def getMemoryReads(self):
        return self.reads
    
    def getMemoryWrites(self):
        return self.writes

    def getChunks(self):
        """
        Get the interesting chunks. These are the ones logged by the 'A:' record.
        """
        return self.chunks

    def getResolvedBranches(self):
        return self.resolves
        
    def getLoadedImages(self):
        return self.images    
    
    def getFunctions(self):
        return self.functions
    
    def getChunkByTimestamp(self, timestamp):
        return self.ts2chunk[timestamp]
            
    def getBasicBlockHits(self):
        return self.hits

    def getFunctionByAddress(self, address):
        return self.addr2function[address]
    
    def removeChunk(self, chunk):
        """
        Verify if it does work.
        """
        for func in self.chunk2function[chunk.timestamp]:
            for use in list(func.chunks_used):
                if use.chunk.timestamp == chunk.timestamp:
                    func.chunks_used.remove(use)
        
        del self.chunk2function[chunk.timestamp]
        del self.ts2chunk[chunk.timestamp]
        self.chunks.remove(chunk)
    
    def removeFunction(self, function):
        pass
    
    def parse(self, match_events=""):
        throughput = 0
        current_bytes = 0
        bytes_processed = 0
        i = 0
        start_time = time()
        cur_time = time()

        self.f = open(self.filename, "r")
        
        debug("Parsing trace file %s of size %f MB" % (self.filename, float(self.file_size) / 1024.0 / 1024.0))
                
        for line in self.f:
            if bytes_processed > self.size_limit and self.size_limit != 0:
                debug("Reached trace file size limit of %d mega-bytes" % (self.size_limit / 1024 / 1024))
                break
            
            event = line[0]
            
            bytes_processed += len(line)
            current_bytes += len(line)
            
            i += 1
            if (i % 500000) == 0:
                throughput = (float(current_bytes) / 1024.0 / 1024.0)/ (time() - cur_time)
                debug("Processed %3d percent of trace file at %3d mb/s" % (bytes_processed * 100 / self.file_size, throughput))
                cur_time = time()
                current_bytes = 0
        
            if (event not in match_events) and (match_events != ""):
                continue
        
            if event not in self.allowed_events:
                continue
            elif event == "H":
                # Basic Block hit event.
                fields      = line.split(";")
                address     = int(fields[1], 16)
                
                new_object = BasicBlockHit(address)
                self.hits.append(new_object)

            elif event == "D":
                # Destructor function detected.
                fields      = line.split(";")
                func_addr   = int(fields[1], 16)
                
                new_object = Destructor(func_addr)
                self.destructors.append(new_object)
                
            elif event == "F":
                # Function detected
                fields      = line.split(";")
                func_addr   = int(fields[1], 16)
                
                new_object = Function(func_addr)
                self.functions.append(new_object)
                self.addr2function[func_addr] = new_object
                
            elif event == "I":
                # Interesting chunk. Might be a method. At least it deals with the chunk.
                # Sample line: I:0x00000000004006b8:0x0000000000000001:0x0000000000000000
                fields     = line.strip().split(";")
                ins_addr   = int(fields[1], 16)
                timestamp  = int(fields[2], 16)
                offset     = int(fields[3], 16)
                                
                chunk = self.getChunkByTimestamp(timestamp)
                
                if not chunk:
                    raise Exception("Could not find chunk with time stamp %d" % timestamp)
                
                new_object = InterestingFunction(ins_addr, chunk, offset)
                
                function = self.getFunctionByAddress(ins_addr)
                
                if not function:
                    raise Exception("Could not find function with address 0x%x" % ins_addr)
                
                function.chunks_used.append(new_object)
                
                # Create an index to quickly get the set of functions that deal with a chunk.
                self.chunk2function.setdefault(timestamp, set()).add(function)
                
            elif event == "L":
                # Loaded a new image.
                # Sample line:  L:ld-linux-x86-64.so.2:0x00007fbeb7461000:0x00007fbeb76832c7
                fields      = line.split(";")
                img_name    = fields[1]
                img_lo      = int(fields[2], 16)
                img_hi      = int(fields[3], 16)
                
                new_object = LoadedImage(img_name, img_lo, img_hi)
                self.images.append(new_object)
                
            elif event == "W":
                # Write to an interesting chunk. This indicates a field inside the chunk
                # Sample line:  W:0x004776c6:0x01e01558:0x01e01558:0x00000004:0x00000019:0x004777f4:0x00000016
                fields      = line.split(";")
                ins_addr    = int(fields[1], 16)
                chunk_addr  = int(fields[2], 16)
                write_addr  = int(fields[3], 16)
                write_size  = int(fields[4], 16)
                timestamp   = int(fields[5], 16)
                content     = int(fields[6], 16)
                chunk_ref   = int(fields[7], 16)
                
                # NOTE: This should only be enabled for traces with too many entries to process.
                #if write_addr in seen_addresses:
                #    continue
                #seen_addresses.add(write_addr)
                
                new_object = WriteAccess(ins_addr, chunk_addr, timestamp, write_addr, write_size, content, chunk_ref)
                self.writes.append(new_object)
                
            elif event == "R":
                # Read to an interesting chunk.
                # Sample line:  R:0x000000000040081a:0x0000000001a2c010:0x0000000000000004:0x0000000000000004
                fields      = line.split(";")
                ins_addr    = int(fields[1], 16)
                chunk_addr  = int(fields[2], 16)
                read_addr   = int(fields[3], 16)
                read_size   = int(fields[4], 16)
                timestamp   = int(fields[5], 16)
                content     = int(fields[6], 16)
                chunk_ref   = int(fields[7], 16)
                
                new_object = ReadAccess(ins_addr, chunk_addr, timestamp, read_addr, read_size, content, chunk_ref)
                self.reads.append(new_object)
                
            elif event == "A":
                # Interesting heap chunk. One that has been identified as a potential object
                # Sample line:  A:0x0000000001a2c010:0x000000000000000c:0x000000000000000c
                fields      = line.strip().split(";")
                chunk_addr  = int(fields[1], 16)
                chunk_size  = int(fields[2], 16)
                timestamp   = int(fields[3], 16)
                
                new_object = InterestingChunk(chunk_addr, chunk_size, timestamp)
                self.chunks.append(new_object)
                self.ts2chunk[timestamp] = new_object
                                
            elif event == "X":
                # Resolved indirect jump/call.
                # Sample line:  X:<instruction_address>:<branch_address>
                fields      = line.strip().split(";")
                ins_addr    = int(fields[1], 16)
                branch_addr = int(fields[2], 16)
                               
                new_object = ResolvedIndirectBranch(ins_addr, branch_addr)
                self.resolves.append(new_object)    

            elif event == "T":
                # Tainted instruction
                fields      = line.strip().split(";")
                ins_addr    = int(fields[1], 16)

                new_object = TaintedInstruction(ins_addr)
                self.tainted.append(new_object)
        
        debug("Processed %3d percent of trace file at %3d mb/s" % (100, throughput))
        debug("Trace loading took %d seconds" % (time() - start_time))
                
        debug("Building 'write to chunk' index")
        chunk_cache = {}
        for write in self.getMemoryWrites():
            chunk = chunk_cache.get(write.timestamp, None)
            if not chunk:
                try:
                    chunk = self.getChunkByTimestamp(write.timestamp)
                except KeyError:
                    continue
                
                chunk_cache[write.timestamp] = chunk

            # NOTE: This is a weird error.
            if not chunk:
                continue
                
            # Save a reference to the memory writes to this chunk
            chunk.writes.append(write)
                        
        debug("Finished building indexes")

        self.f.close()
        