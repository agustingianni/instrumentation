'''
Created on Jun 5, 2012

@author: gr00vy
'''
from logging import info
from time import time
from sqlalchemy import Column, Integer, String, BigInteger, LargeBinary
from sqlalchemy import ForeignKey, Sequence
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import ProgrammingError
from db import engine
from struct import pack, unpack

Base = declarative_base()

class ResolvedBranch(Base):
    """
    Describes a resolved indirect branch such ass "jmp eax" or "call [mem]" etc.
    """

    __tablename__ = "resolvedbranches"
    
    id            = Column(Integer, Sequence("resolvedbranches_id_seq"), primary_key=True)
    rva           = Column(BigInteger)
    branch_rva    = Column(BigInteger)
        
    # We need these for the "primaryjoin" expression in the class Module
    module_id        = Column(Integer, ForeignKey("modules.id"))
    branch_module_id = Column(Integer, ForeignKey("modules.id"))
    
    def __init__(self, module, rva, branch_module, branch_rva):
        self.module        = module
        self.rva           = rva
        self.branch_module = branch_module
        self.branch_rva    = branch_rva
        
    def __repr__(self):        
        return "ResolvedBranch: module=%s, rva=%x, branch_module=%s, branch_rva=%x" % \
            (self.module.name, self.rva, self.branch_module.name, self.branch_rva)

class BasicBlockHit(Base):
    __tablename__ = "basicblockhits"
    
    id        = Column(Integer, Sequence("basicblocks_id_seq"), primary_key=True)
    rva       = Column(BigInteger)
    module_id = Column(Integer, ForeignKey("modules.id"))

    def __init__(self, module, rva):
        self.module = module
        self.rva    = rva

    def __repr__(self):
        return "BasicBlockHit: module=%s, rva=%x" % (self.module.name, self.rva)

class Destructor(Base):
    __tablename__ = "destructors"
    
    id        = Column(Integer, Sequence("destructors_id_seq"), primary_key=True)
    rva       = Column(BigInteger)
    module_id = Column(Integer, ForeignKey("modules.id"))
    
    def __init__(self, module, rva):
        self.module = module
        self.rva = rva
        
    def __repr__(self):
        return "Destructor: module=%s, rva=%x" % (self.module.name, self.rva)

class Function(Base):
    """
    Describes a function called by the program.
    """
    __tablename__ = "functions"
    
    id         = Column(Integer, Sequence("functions_id_seq"), primary_key=True)
    rva        = Column(BigInteger)
    module_id  = Column(Integer, ForeignKey("modules.id"))

    # List of all the chunks used as "this" by this function.
    uses = relationship("FunctionUse", order_by="FunctionUse.id", backref="function", lazy="dynamic")

    def __init__(self, module, rva):
        self.module = module
        self.rva    = rva
        
    def __repr__(self):
        return "Function: module=%s, rva=%x" % (self.module.name, self.rva)

class FunctionUse(Base):
    """
    A Function use is an instance of a function call that receives as a 
    parameter a pointer to one of our chunks.
    """    
    __tablename__ = "functionuses"

    id          = Column(Integer, Sequence("functionuses_id_seq"), primary_key=True)
    function_id = Column(Integer, ForeignKey("functions.id"))
    chunk_id    = Column(Integer, ForeignKey("memorychunks.id"))
    offset      = Column(BigInteger)
    
    def __init__(self, function, chunk, offset):
        self.function = function
        self.chunk    = chunk
        self.offset   = offset
        
    def __repr__(self):
        return "FunctionUse: function=%x, chunk=%x, offset=%x" % \
            (self.function.id, self.chunk.id, self.offset)

class Module(Base):
    __tablename__ = "modules"

    id = Column(Integer, Sequence("modules_id_seq"), primary_key=True)

    name    = Column(String(256), unique=True)
    lo_addr = Column(BigInteger)
    hi_addr = Column(BigInteger)

    # List of all the resolved branches on this module, ie all the rva's for things like call eax, etc.
    resolved_branches = relationship("ResolvedBranch", order_by="ResolvedBranch.rva", backref="module", \
            primaryjoin="ResolvedBranch.module_id == Module.id", lazy="dynamic")
    
    # List of all the indirect branches made into an instruction in this module.
    indirect_branches = relationship("ResolvedBranch", order_by="ResolvedBranch.rva", backref="branch_module", \
            primaryjoin="ResolvedBranch.branch_module_id == Module.id", lazy="dynamic")
    
    # List of all the basic blocks that were hit in the trace.
    basicblock_hits = relationship("BasicBlockHit", order_by="BasicBlockHit.rva", backref="module", \
            lazy="dynamic")
    
    # List of all destructors found on this module
    destructors = relationship("Destructor", order_by="Destructor.rva", backref="module", lazy="dynamic")
    
    # List of all functions on this module
    functions = relationship("Function", order_by="Function.rva", backref="module", lazy="dynamic")
    
    # List of all the memory accesses made by this module
    memory_accesses = relationship("MemoryAccess", order_by="MemoryAccess.rva", backref="module", lazy="dynamic")
    
    def __init__(self, name, lo_addr=0, hi_addr=0):
        self.name    = name
        self.lo_addr = lo_addr
        self.hi_addr = hi_addr
        
    def __repr__(self):
        return "Module: id=%x, name=%s, lo_addr=%x, hi_addr=%x" % (self.id, self.name, self.lo_addr, self.hi_addr)
        
class MemoryChunk(Base):
    __tablename__ = "memorychunks"

    id        = Column(Integer, Sequence("memorychunks_id_seq"), primary_key=True)
    size      = Column(BigInteger)
    timestamp = Column(BigInteger, index=True, unique=True)
    
    # Add a relationship with the memory accesses
    accesses  = relationship("MemoryAccess", order_by="MemoryAccess.rva", backref="chunk", lazy="dynamic")
    uses      = relationship("FunctionUse", order_by="FunctionUse.id", backref="chunk", lazy="dynamic")
     
    def __init__(self, timestamp, size):
        self.timestamp = timestamp
        self.size      = size
        
    def __repr__(self):
        return "MemoryChunk: timestamp=%x, size=%x" % (self.timestamp, self.size)
    
class MemoryAccess(Base):
    __tablename__ = "memoryaccesses"
    
    # Access types
    READ  = 0
    WRITE = 1
    
    id         = Column(Integer, Sequence("memoryaccesses_id_seq"), primary_key=True)
    type       = Column(Integer)
    rva        = Column(BigInteger)
    
    module_id  = Column(Integer, ForeignKey("modules.id"))
    chunk_id   = Column(Integer, ForeignKey("memorychunks.id"))
    
    offset     = Column(BigInteger)
    size       = Column(BigInteger)
    
    # This is because in SQLite 64bit integer are signed.
    content    = Column(LargeBinary(8))
    
    def __init__(self, type, module, rva, chunk, offset, size, content):
        self.type    = type
        self.module  = module
        self.rva     = rva
        self.chunk   = chunk
        self.offset  = offset
        self.size    = size
        self.content = content
        
    def __repr__(self):
        return "MemoryAccess: type=%s, chunk=%x, module=%s, rva=%x, offset=%x, size=%x, content=%x" % \
            (self.__type_to_string__(type), self.chunk.timestamp, self.module.name, 
             self.rva, self.offset, self.size, unpack("<Q", self.content)[0])
    
    def __type_to_string__(self, type):
        if type == MemoryAccess.READ:
            return "Read"        
        return "Write"

from trace_.TraceReader import LoadedImage
from helpers.AddressResolver import AddressResolver
from db import Session

class TraceReader:
    """
    This class will load a trace file and parse it. It will store everything in a database. 
    """
    def __init__(self, filename, database_name="default_trace"):
        self.filename = filename
        self.address_resolver = AddressResolver()
        self.session = Session()
        
        self.cache = {}
        self.cache["chunks"] = {}
        self.cache["modules"] = {}
         
        # these are the events that we currently load from the trace file
        self.allowed_events = ["L", "W", "R", "I", "A", "X", "F", "D", "H"]
        
        """
        try:
            conn = engine.connect()
            conn.execute("commit")
            conn.execute("create database %s" % (database_name))
        except ProgrammingError:
            raise RuntimeWarning("Error while creating database %s, it already exists" % (database_name))
        finally:
            conn.close()
        """

    def parse(self, match_events=""):
        self.f = open(self.filename, "r")
        
        info("Parsing trace file %s" % self.filename)
        
        i = 0
        start_time = time()
        
        print  self.session.query(MemoryChunk).filter(MemoryChunk.timestamp == 0xcafecafe)
        
        # First pass. Collect functions and chunks        
        for line in self.f:
            event = line[1]
            
            i += 1
            if (i % 100000) == 0:
                print "Number of lines processed %d in %d seconds" % (i, time() - start_time)
        
            if (event not in match_events) and (match_events != ""):
                continue
        
            if event not in self.allowed_events:
                continue
            elif event == "H":
                # Basic Block hit event.
                fields     = line.split(":")
                address    = int(fields[1], 16)
                
                image      = self.address_resolver.get_image(address)
                rva        = image.get_offset(address)
                
                # Get the backing module. There should be just one module, otherwise an exception will be raised.
                module     = self.session.query(Module).filter(Module.name == image.name).one()                
                new_object = BasicBlockHit(module, rva)
                
            elif event == "D":
                # Destructor function detected.
                # Sample line: D:RVA
                fields     = line.split(":")
                address    = int(fields[1], 16)
                
                image      = self.address_resolver.get_image(address)
                rva        = image.get_offset(address)
                
                # Get the backing module. There should be just one module, otherwise an exception will be raised.
                module     = self.session.query(Module).filter(Module.name == image.name).one()
                new_object = Destructor(module, rva)
                                
            elif event == "F":
                # Function detected
                # Sample line: F:RVA
                fields     = line.split(":")
                address    = int(fields[1], 16)
                
                image      = self.address_resolver.get_image(address)
                rva        = image.get_offset(address)

                # Get the backing module. There should be just one module, otherwise an exception will be raised.
                module     = self.session.query(Module).filter(Module.name == image.name).one()

                new_object = Function(module, rva)
                                
            elif event == "L":
                # Loaded a new image.
                # Sample line:  L:ld-linux-x86-64.so.2:0x00007fbeb7461000:0x00007fbeb76832c7
                fields      = line.split(":")
                img_name    = fields[1]
                img_lo      = int(fields[2], 16)
                img_hi      = int(fields[3], 16)
                
                # Add a new image to the address resolver. Used to get the RVA of most things
                self.address_resolver.loaded_image(LoadedImage(img_name, img_lo, img_hi))
                
                new_object = Module(img_name, img_lo, img_hi)

            elif event == "A":
                # Interesting heap chunk. One that has been identified as a potential object
                # Sample line:  A:0x0000000001a2c010:0x000000000000000c:0x000000000000000c
                fields      = line.strip().split(":")
                chunk_addr  = int(fields[1], 16)
                chunk_size  = int(fields[2], 16)
                timestamp   = int(fields[3], 16)
                
                new_object = MemoryChunk(timestamp, chunk_size)
                                
            elif event == "X":
                # Resolved indirect jump/call.
                # Sample line:  X:ID:RVA:ID:RVA
                fields         = line.strip().split(":")
                ins_address    = int(fields[1], 16)
                branch_address = int(fields[2], 16)

                image          = self.address_resolver.get_image(ins_address)
                ins_rva        = image.get_offset(ins_address)
                
                try:
                    branch_image  = self.address_resolver.get_image(branch_address)
                    branch_rva    = branch_image.get_offset(branch_address)                    
                    branch_module = self.session.query(Module).filter(Module.name == branch_image.name).one()
                except AttributeError:
                    branch_rva    = 0
                    branch_module = Module("InvalidModule", 0, 0)
                
                module = self.session.query(Module).filter(Module.name == image.name).one()
                               
                new_object = ResolvedBranch(module, ins_rva, branch_module, branch_rva)
            else:
                continue
            
            self.session.add(new_object)
            self.session.flush()
    
            # Commit current changes.
            self.session.commit()
        
        return
    
        
        i = 0
        start_time = time()        
        self.f.seek(0)
        
        print "Second pass analysis"
        
        # Second pass analysis
        for line in self.f:
            event = line[1]
            
            i += 1
            if (i % 1000) == 0:
                print "Number of lines processed %d in %d seconds" % (i, time() - start_time)
        
            if (event not in match_events) and (match_events != ""):
                continue
        
            if event not in self.allowed_events:
                continue
            elif event == "I":
                # Interesting address. Might be a method. At least it deals with the chunk.
                # Sample line: I:0x00000000004006b8:0x0000000000000001:0x0000000000000000
                fields     = line.strip().split(":")
                address    = int(fields[1], 16)
                timestamp  = int(fields[2], 16)
                offset     = int(fields[3], 16)

                image      = self.address_resolver.get_image(address)
                rva        = image.get_offset(address)

                # Get the function that used the chunk. There must be only one function, otherwise an exception will be raised.
                function   = self.session.query(Function).filter(Module.name == image.name).filter(Function.rva == rva).one()
                chunk      = self.session.query(MemoryChunk).filter(MemoryChunk.timestamp == timestamp).one()
                
                new_object = FunctionUse(function, chunk, offset)
                
            elif event == "W" or event == "R":
                # Write or read to an interesting chunk. This indicates a field inside the chunk
                # Sample line:  W:0x004776c6:0x01e01558:0x01e01558:0x00000004:0x00000019:0x004777f4:0x00000016
                fields     = line.split(":")
                address    = int(fields[1], 16)
                chunk_addr = int(fields[2], 16)
                write_addr = int(fields[3], 16)
                write_size = int(fields[4], 16)
                timestamp  = int(fields[5], 16)
                content    = pack("<Q", int(fields[6], 16))

                image      = self.address_resolver.get_image(address)
                rva        = image.get_offset(address)
                            
                type = MemoryAccess.WRITE
                if event == "R":
                    type = MemoryAccess.READ

                if not self.cache["chunks"].has_key(timestamp):
                    chunk = self.session.query(MemoryChunk).filter(MemoryChunk.timestamp == timestamp).one()
                    self.cache["chunks"][timestamp] = chunk
                else:
                    chunk = self.cache["chunks"][timestamp]

                if not self.cache["modules"].has_key(image.name):
                    module = self.session.query(Module).filter(Module.name == image.name).one()
                    self.cache["modules"][image.name] = module
                else:
                    module = self.cache["modules"][image.name]


                #module     = self.session.query(Module).filter(Module.name == image.name).one()
                
                offset     = write_addr - chunk_addr
                
                new_object = MemoryAccess(type, module, rva, chunk, offset, write_size, content)
            else:
                continue
                
            self.session.add(new_object)
            self.session.flush()
        
        self.session.commit()        
        self.f.close()
        
Base.metadata.create_all(engine)

def main():
    reader = TraceReader("C:\\Users\\gr00vy\\Desktop\\AssortedShit\\Recoverer\\pintool.log")
    reader.parse()

if __name__ == '__main__':
    main()
    
    """

    # Create a new session, this is like the db handle.
    session = Session()
    
    module = Module("c:\\pepe.dll", "pepe.dll")
    branch_module = Module("c:\\branch.dll", "branch.dll")
    chunk = MemoryChunk(0xCCCCCCCC, 0xff)
    function = Function(module, 0x0badc0de)
    
    session.add(module)
    session.add(function)
    session.add(branch_module)
    session.add(chunk)

    print function
    print chunk
    print branch_module
    print module
    
    for i in xrange(0, 0x10):
        access = MemoryAccess(MemoryAccess.READ, module, 0xdddd0000 + i, chunk, 0, 4, 0xcaca0000 + i)
        use = FunctionUse(function, chunk, 0x00)
        session.add(access)
        
    print "Memory accesses for chunk %s" % (chunk)
    for access in chunk.accesses:
        print "  %s" % (access)
        
    session.commit()

    for i in xrange(0, 0x10):
        branch = ResolvedBranch(module, 0xcafe0000 + i, branch_module, 0xdead0000 + i)
        bblock_hit = BasicBlockHit(module, 0xaaaa0000 + i)
        destructor = Destructor(module, 0xbbbb0000 + i)
        function = Function(module, 0xcccc0000 + i)
        session.add(bblock_hit)
        session.add(destructor)
        session.add(function)
        session.add(branch)
    
    session.commit()
    
    print "Basic block hits for module %s" % (module)
    for bblock_hit in module.basicblock_hits:
        print "  %s" % (bblock_hit)

    print "Destructors for module %s" % (module)
    for destructor in module.destructors:
        print "  %s" % (destructor)
    
    print "Functions for module %s" % (module)
    for functions in module.functions:
        print "  %s" % (functions)

    print "Resolved branches for module %s" % (branch_module)
    for resolved_branch in module.resolved_branches:
        print "  %s" % (resolved_branch)

    print "Indirect branches for module %s" % (branch_module)
    for indirect_branch in branch_module.indirect_branches:
        print "  %s" % (indirect_branch)
    
    #print branch
    """
    