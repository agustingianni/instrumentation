'''
Created on Mar 12, 2012

@author: gr00vy
'''

from helpers.AddressResolver import AddressResolver
from logging import info, debug
from sa.codegraph import CCONV_THISCALL

def GetTypeFromSize(size):
    """
    Convert a give size to a standard C type.
    """
    return "uint%d_t" % (size * 8)

class FieldType:
    """
    Describes a field of a class. This holds important information gathered from
    the trace.
    
    @size      : indicates the size of the field
    @offset    : indicates the offset from the begining of the chunk
    @vtable    : if this object writes a vtable.
    @def_write : write memory access that defined this field
    """
    def __init__(self, size, offset, vtable, def_write, ref_chunk):
        self.size = size
        self.offset = offset
        self.vtable = vtable
        self.def_write = def_write
        self.values = set()
        self.ref_chunks = set()
        
        if ref_chunk:
            self.ref_chunks.add(ref_chunk)
        
        if size <= 0 or offset < 0:
            raise Exception("Field size is <= 0")

        self.addValue(self.def_write.content)
    
    def isVTable(self):
        """Return if the object is a vtable pointer"""
        return self.vtable != None
    
    def isPointer(self):
        """Return if the field is a pointer to a heap object"""
        return len(self.ref_chunks) != 0
    
    def addValue(self, value):
        self.values.add(value)
    
    def addReferencedChunk(self, ref_chunk):
        self.ref_chunks.add(ref_chunk)
    
    def toCString(self):    
        ret = ""
                
        vals = ""
        if len(self.values):            
            vals = "// values: " + ",".join(map(lambda x: "0x%x" % x, self.values))
            if self.isVTable():
                vals += " (VTABLE)"
        
        if self.isPointer():
            ret += "%8s field_%.2x_%.2x; %s" % ("void *", self.size, self.offset, vals) 
        else:
            ret += "%8s field_%.2x_%.2x; %s" % (GetTypeFromSize(self.size), self.size, self.offset, vals)
        
        return ret
    
    def __repr__(self):
        # TODO FIXME
        return self.toCString()
    
        ret = "FieltType(offset=%x, size=%x, is_vtable=%r, is_pointer=%r)\n" \
            % (self.offset, self.size, self.isVTable(), self.isPointer())

        # , str(self.values), str(self.ref_chunks)
        if len(self.values):
            ret += "Values %r\n" % self.values
            
        if len(self.ref_chunks):
            ret += "Referenced chunks = %r\n" % self.ref_chunks
            
        return ret
    
    def __eq__(self, rhs):
        return (self.offset == rhs.offset and self.size == rhs.size)
    
    def __hash__(self):
        return hash((self.offset, self.size))
    
    def __lt__(self, rhs):
        if self.offset == rhs.offset:
            return self.size < rhs.size 

        return self.offset < rhs.offset

class ClassType:
    """
    Describes a new class. A class contains a set of methods and fields.
    
      - Fuck you Guido.
    """
    def __init__(self, name, size=0, methods=None, fields=None, related=None, comment=None, variable_size=False):
        """
        @name:     name of the type
        @size:     size of the type
        @methods:  methods of the type
        @fields:   fuck it
        @related:  populated if this type is the result of a type merge
        @comment:  additional comments about the type
        """
        if size <= 0:
            raise Exception("Field size is <= 0")
        
        self.variable_size = variable_size
        
        self.is_complete = False
        
        self.num_unions = 0
        self.name = name
        self.size = size
        
        if not comment: comment = ""
        self.comment = comment
        
        if not fields:  fields = []
        self.fields = fields
        
        if not methods: methods = set()
        self.methods = methods
        
        if not related: related = set()
        self.related = set()
        
        to_add = set()
        for r1 in related:
            if len(r1.getRelated()):
                to_add.update(r1.getRelated())
            else:
                to_add.add(r1)
                
        self.related.update(to_add)
            
    def isComplete(self):
        return self.is_complete

    def __hash__(self):
        return hash(self.name)

    def getRelated(self):
        return self.related
    
    def getMethods(self):
        return self.methods
        
    def getFields(self):
        return self.fields
    
    def getField(self, offset, size):
        for field in self.fields:
            if field.offset == offset and field.size == size:
                return field
            
        return None

    def resize(self, new_size):
        for field in self.fields:
            if field.offset + field.size > new_size:
                return False
        
        self.size = new_size
        return True
    
    def addField(self, field):
        """
        Add a field to the type. A memory write is considered a field on the chunk.
        There could be multiple writes to the same offset. They could also have
        a different size, this usually means that the chunk has been passed to
        a memset or memcpy like routine.
        
        We should take this into account and form a union with the different sizes.
        This is future work.
        """
        # Sanity check
        if field.offset + field.size > self.size:
            raise Exception("The field about to be added has an offset bigger than the class type")
        
        if not self.isComplete():
            self.is_complete = True
        
        if filter(lambda e: e.offset == field.offset and e.size == field.size, self.fields):
            raise Exception("Trying to add a duplicate field at offset %d and size %d" % (field.offset, field.size))
        
        self.fields.append(field)

    def addMethods(self, methods):
        for m in methods:
            self.addMethod(m)
        
    def addMethod(self, address):
        self.methods.add(address)

    def addRelatedType(self, related):
        self.related.add(related)

    def __build_fields__(self):    
        ret = "  // Detected fields\n"

        offsets = {}
        for field in self.fields:
            offsets.setdefault(field.offset, []).append(field)
        
        tmp = []        
        for offset in sorted(offsets.keys()):
            t = ""
            
            # If there is more than one element at 'offset' create a new union.
            if len(offsets[offset]) > 1:
                size = max(map(lambda x: x.size, offsets[offset]))
                t += "  union\n  {\n"
                for e in offsets[offset]:
                    t += "    " + str(e) + "\n"
            else:
                for e in offsets[offset]:
                    size = e.size
                    t += "  " + str(e)
                
            if len(offsets[offset]) > 1:
                t += "  } u_%d;\n" % (self.num_unions)
                self.num_unions += 1
            
            # Append a triplet
            tmp.append((offset, size, t))
            
        # Add padding at the begining if needed. tmp[0][0] is the offset of the first field
        pad = tmp[0][0]
        if pad < 0:
            raise Exception("Error, beggining pad is less than zero")
        
        if pad:
            ret += "  uint8_t  pad_beg[%d]; // padding\n" % pad

        for i in xrange(0, len(tmp)):
            field = tmp[i]
            ret += field[2]
            
            if i + 1 < len(tmp):
                #     next.offset - (this.offset + this.size)
                pad = tmp[i + 1][0] - (field[0] + field[1])
                
                if pad < 0:
                    raise Exception("Error, inbetween padding is less than zero")
                
                if pad:
                    ret += "  uint8_t  pad_%d[%d]; // padding\n" % (i, pad)

            
        pad = self.size - (tmp[-1][0] + tmp[-1][1])
        if pad < 0:
            raise Exception("Error, end pad is less than zero")
        
        if pad:
            ret += "  uint8_t  pad_end[%d]; // padding\n" % pad

        return ret
    
    def __build_additional__(self):
        header = "// Additional information\n"
        header += "// " + self.comment + "\n"
        header += "// Type size %x\n" % self.size

        return header
    
    def toCString(self):
        if not len(self.fields):
            return "struct %s\n{    char unknown[%d];\n};" % (self.name, self.size)
            
        ret = self.__build_additional__() + \
        """struct %s
{
""" % self.name
        
        ret += self.__build_fields__()                    
        ret += "};\n"

        return ret 
    
    def __repr__(self):
        return self.toCString()
        
        ret = "ClassType(name=%s, size=%x, methods=%s)\n" \
            % (self.name, self.size, str(self.methods))
        
        # , str(self.fields), str(self.related)
        for field in self.fields:
            ret += "%r\n" % field

        return ret
    
class ObjectTyper:
    """
    Helper class to keep track of already assigned types.
    """
    def __init__(self):
        self.types = []
        self.i = 0
        self.composite_count = 0
        self.pad_count = 0
        
    def getDefaultClassType(self):
        return ClassType("UnknownClass")
    
    def getNonUniformType(self, sizes):
        self.i += 1
        return ClassType("Class_%d" % self.i, size=max(sizes), variable_size=True)        
    
    def getType(self, size):
        if size <= 0:
            raise Exception("Cannot create a type of size %d" % size)
        
        self.i += 1
        return ClassType("Class_%d" % self.i, size)
    
    def getPadType(self, size):
        if size <= 0:
            raise Exception("Cannot create pad of size %d" % size)
    
        self.pad_count += 1
        return ClassType("Pad_%d" % self.pad_count, size)
    
    def createCompositeType(self, size):
        if size <= 0:
            raise Exception("Cannot create a composite type of size %d" % size)
        
        self.composite_count += 1
        return CompositeType("Composite_%d" % self.composite_count, size)
    
    def __merge_fields__(self, type_a, type_b):
        return list(set(type_a.getFields() + type_b.getFields()))
    
    def mergeTypes(self, type_a, type_b):
        # Check if we are trying to merge to size differing sizes.
        if type_a.size != type_b.size:
            raise Exception("Cannot merge types of different sizes")

        # Union of the set of methods.
        merged_methods = type_a.getMethods() | type_b.getMethods()
        
        # Concatenation of the list of fields. Later on we are going to solve any inconsistences.
        merged_fields = self.__merge_fields__(type_a, type_b)
        
        # Create an unoriginal name.
        merged_name = "Merged_%d" % (self.i)
        
        self.i += 1
        
        new_type = ClassType(merged_name, type_a.size, merged_methods, merged_fields, set([type_a, type_b]))

        # Build a comment with the shared methods
        shared_methods = type_a.getMethods() & type_b.getMethods()
        new_type.comment += "Shared methods:\n// "
        for m in shared_methods:
            new_type.comment += "0x%x " % m
        
        return new_type
    
class CompositeType:
    def __init__(self, name, size):
        if size <= 0:
            raise Exception("Field size is <= 0")
        
        self.name = name
        self.size = size
        self.subtypes = {}
        
    def fillGaps(self, typer):
        cur_off = 0
        cur_size = 0
        
        offsets = sorted(map(lambda x: (x, self.subtypes[x].size), self.subtypes.keys()) + [(self.size, 0)])
        
        i = 0
        while i < len(offsets):
            if cur_off + cur_size != offsets[i][0]:
                size = offsets[i][0] - (cur_off + cur_size)
                if size <= 0:
                    raise Exception("size <= 0 while filling gaps")
                
                chunk_type = typer.getType(size)
                self.addType(cur_off + cur_size, chunk_type)
            
            cur_off = offsets[i][0]
            cur_size = offsets[i][1]
            
            i += 1

    def isComplete(self):
        return self.size == sum(map(lambda x: x.size, self.subtypes.values()))

    def replaceType(self, old_type, new_type):
        if old_type.size != new_type.size:
            raise Exception("Cannot replace two different sized types")

        for key in self.subtypes.iterkeys():
            if self.subtypes[key].name == old_type.name:
                #debug("Replaced %s (size %x) with %s (size %x) " % (old_type.name, old_type.size, new_type.name, new_type.size))
                self.subtypes[key] = new_type

    def getNextTypeOffset(self, offset):
        for key in sorted(self.subtypes.keys()):
            if key > offset:
                return key
            
        return self.size
    
    def getNextType(self, offset):
        offset = self.getNextTypeOffset(offset)
        return self.getTypeAtOffset(offset)
    
    def addType(self, offset, chunk_type):
        if self.subtypes.has_key(offset):
            debug("Offset %d already had a type, returning the previous type" % offset)
            return self.subtypes[offset]
        
        self.subtypes[offset] = chunk_type
        return self.subtypes[offset]
    
    def getTypeAtOffset(self, offset, fix_offset=False):
        if not fix_offset:
            if not self.subtypes.has_key(offset):
                return None
            
            return self.subtypes[offset]
        else:
            for (key, val) in self.subtypes.iteritems():
                if offset >= key and (offset < (key + val.size)):
                    return self.subtypes[key]
    
    def getTypeAndOffsetAtOffset(self, offset):            
            for (key, val) in self.subtypes.iteritems():
                if offset >= key and (offset < (key + val.size)):
                    return (key, val)
    
    def shouldSplit(self, offset):
        """
        Return if the give offset falls into the middle of a type.
        Exclude the begining offset and the last byte.
        """
        for (key, val) in self.subtypes.iteritems():
            if key < offset and (offset < (key + val.size)):
                return True
            
        return False
    
    def toCString(self):
        ret = "struct %s\n{\n" % (self.name)
        
        for subtype in self.subtypes.itervalues():
            ret += str(subtype)           
        
        ret += "};"
        return ret

    def __repr__(self):
        ret = "CompositeType(name=%s, size=%x)\n" \
            % (self.name, self.size)
        
        for key, subtype in self.subtypes.items():
            ret += "%d, %r\n" % (key, subtype)
        
        return ret

    def __eq__(self, rhs):
        return (self.name == rhs.name)
    
    def __hash__(self):
        tmp = ""
        
        for i in self.subtypes.values():
            tmp += i.name
            
        return hash(tmp)
    
class TypeReconstructor:
    def __init__(self, settings, trace, ida_db):
        self.settings = settings
        self.ida_db = ida_db
        self.infered_types = []
        self.trace = trace
        self.resolver = AddressResolver(self.trace.getLoadedImages())
        self.typer = ObjectTyper()
        self.merged_types = []
        
        self.chunk_sizes = set()
    
        self.composite_types = set()
        self.type_constraints = {}
    
    def getInferedTypes(self):
        return self.infered_types

    def __purgue_no_access_chunks__(self):
        """
        This may or may not be used. Currently it is not.
        What it does is to check for function calls receiveing
        a chunk but not doing anything on it (ie. do not access it).
        """
        for write in self.trace.getMemoryWrites():
            rva = self.resolver.get_rva(write.ins_addr)
            function = self.ida_db.get_function_by_rva(rva)
            
            if not function:
                info("There is no function for address %x in IDA Pro database." % (self.ida_db.get_image_base() + rva))
                continue
                
            #info("There is no function for address %x in IDA Pro database." % (self.ida_db.get_image_base() + rva))
            image = self.resolver.get_image(write.ins_addr)
            
            # Get the function from the trace file, this is different from the one above.
            try:
                f = self.trace.getFunctionByAddress(image.lo_addr + function.start)
            except KeyError:
                debug("Read from %x" % (self.ida_db.get_image_base() + rva))
                debug("There is no function for address %x in the trace file." % (image.lo_addr + function.start))
                continue            
            
            # This function accessed memory.
            f.accesses_memory = True
        
        ok_functions_len = len(filter(lambda x: x.accesses_memory == True, self.trace.getFunctions()))
        all_function_len = len(self.trace.getFunctions())
        
        info("Number of functions is %d vs the number of functions with memory accesses %d" % (all_function_len, ok_functions_len))
        
        for function in filter(lambda x: x.accesses_memory == False, self.trace.getFunctions()):
            rva = self.resolver.get_rva(function.ins_addr)
            f = self.ida_db.get_function_by_rva(rva)
            
            print "%x %s" % (f.start + self.ida_db.get_image_base(), f.name)
            
    def __purgue_chunks__(self):
        """
        Remove chunks with no writes or reads. Also remove chunks that due to
        function pruning were left without a function.
        """
        removed = 0
        
        saved_chunk = []
        for chunk in self.trace.chunks:
            # If we have at least one write this is interesting
            if len(chunk.writes):
                saved_chunk.append(chunk)
            else:
                debug("Chunk 0x%.8x was not accessed (write or read) by any function, removing" % chunk.timestamp)
                removed += 1
                
                # Remove the chunk from the cache
                del self.trace.ts2chunk[chunk.timestamp]
                
                def test(x, y):
                    return x == y
                
                # Remove all the chunks from the functions
                for f in self.trace.functions:
                    f.chunks_used[:] = [x for x in f.chunks_used if not test(x.chunk.timestamp, chunk.timestamp)]
        
        info("Number of chunks without memory access removed %d" % (removed))
        
    def __purgue_functions__(self):
        """
        Remove empty functions
        """
        
        a = len(self.trace.functions)
        self.trace.functions[:] = [f for f in self.trace.functions if len(f.chunks_used)]
        
        info("Number of empty functions removed %d" % (a - len(self.trace.functions)))

    def __purgue_fuckups__(self):
        """
        Remove those functions that we know may receive as a parameter one of
        our interesting chunks. That is for example, free, memcpy, etc.
        By removing them we avoid spurious cases like deep copies etc.
        """
        # Remove functions that are known fuckups
        forbidden = ["__EH", "memset", "epilog", "operator delete", "operator new", "ftol", "prolog",
                     "__SEH", "_atexit", "__onexit", "__Fac_tidy", "memcpy", "memmove", "free", "malloc",
                     "__Mtxunlock", "__Mtxlock"]
        
        # All the imports are also forbidden functions
        forbidden += map(lambda x: x.name.split("(")[0], self.ida_db.get_imports())

        # Helper function to check if a given function name is prohibited.
        def is_forbidden(name):
            for deny in forbidden:
                if deny in name:
                    return True
            
            return False
                
        allowed_functions = []    
        for function in self.trace.functions:
            rva = self.resolver.get_rva(function.ins_addr)            
            address_name = self.ida_db.get_address_name(rva)
            rebased_addr = rva + self.ida_db.get_image_base()
                        
            if not is_forbidden(address_name):
                allowed_functions.append(function)
            else:
                info("Removed forbidden function %x : %s" % (rebased_addr, address_name))

        self.trace.functions = allowed_functions

    def __purgue_non_uniform__(self, max_dif_sizes=3):
        """
        Remove functions with chunks of different absolute size.
        The default value is 3 as the maximum number of different
        chunk sizes passed to the function. 
        """
        allowed_functions = []
        for function in self.trace.functions:
            sizes = [(x.chunk.chunk_size - x.offset) for x in function.chunks_used]
            
            # Get the function RVA
            rva = self.resolver.get_rva(function.ins_addr)
            address_name = self.ida_db.get_function_name(rva)
            rebased_addr = rva + self.ida_db.get_image_base()
            
            if len(set(sizes)) > max_dif_sizes:
                if len(address_name) > 24:
                    address_name = address_name[:24] + " ... (name continues)"
                    
                info("Removed function with too many different chunk sizes %s : %x" % (address_name, rebased_addr))
                info("  Chunk sizes %s" % (",".join(map(str, sorted(set(sizes))))))
            else:
                allowed_functions.append(function)
           
        info("Removed %d functions with too many different chunk sizes" % (len(self.trace.functions) - len(allowed_functions)))
             
        self.trace.functions = allowed_functions

    def __purgue_non_thiscall__(self):
        """
        This will purge those functions that were classified as
        non thiscall by our static analyzer.
        """
        total_functions = len(self.trace.functions)
        allowed_functions = []
        
        for function in self.trace.functions:
            rva = self.resolver.get_rva(function.ins_addr)            
            ida_func = self.ida_db.get_function_by_rva(rva)
                 
            if ida_func.cconv == CCONV_THISCALL:
                allowed_functions.append(function)
            else:
                address_name = self.ida_db.get_address_name(rva)
                rebased_addr = rva + self.ida_db.get_image_base()
                
                debug("Removed non thiscall function %x : %s" % (rebased_addr, address_name))                

        info("Number of non thiscall functions removed %d" % (total_functions - len(allowed_functions)))

        self.trace.functions = allowed_functions
    
    def __purgue__(self):
        info("Purging database from undesired entries.")

        # Enable this if you know what you want.
        # self.__purgue_no_access_chunks__()

        # Remove those functions that were ruled out as non thiscall
        self.__purgue_non_thiscall__()

        # Remove non useful chunks.
        self.__purgue_chunks__()

        # Remove functions with no chunks used
        self.__purgue_functions__()

        # Remove functions that we know beforehand will generate fucked up results.
        self.__purgue_fuckups__()
    
        # Remove functions that received too many chunks of different sizes.
        self.__purgue_non_uniform__()
    
    def debug_functions(self):
        for function in self.trace.functions:
            pair = set([(x.chunk.chunk_size, x.offset) for x in function.chunks_used])
            sizes = [(x.chunk.chunk_size - x.offset) for x in function.chunks_used]
            
            # Get the function RVA
            rva = self.resolver.get_rva(function.ins_addr)
            address_name = self.ida_db.get_function_name(rva)
            rebased_addr = rva + self.ida_db.get_image_base()
            
            info("Function %s : %x" % (address_name, rebased_addr))
            info("  Diff Chunk sizes %s" % (",".join(map(str, sorted(set(sizes))))))
            info("  Chunk pairs      %r" % (pair))
            info("  Number of chunks %d" % len(function.chunks_used))
        
    
    def __merge_types__(self, types, merge_dif_sizes=False):
        """
        Given a list of types, join all the types and create a new one
        with the set of all methods. Then replace the original types
        inside the composites for the newly created type
        """
        
        # No need to merge anything
        if len(types) <= 1:
            return types.pop()
        
        # Check if we are trying to merge incompatible types
        sizes = set(map(lambda x: x.size, types))
        if len(sizes) != 1 and not merge_dif_sizes:
            raise Exception("Tried to merge types with different size.")
        
        # Set of all the methods in all the types
        shared_methods = set()
        for t in types:
            shared_methods.update(t.methods)

        # Create a new type, non uniform type if we have multiple sizes
        if len(sizes) > 1:
            new_type = self.typer.getNonUniformType(sizes)
        else:
            new_type = self.typer.getType(sizes.pop())

        new_type.addMethods(shared_methods)

        for composite in self.composite_types:
            for old_type in types:
                composite.replaceType(old_type, new_type)
        
        # Remove the old one from the inferred types
        for old_type in types:
            if old_type in self.infered_types:
                self.infered_types.remove(old_type)
                
        return new_type
    
    def __first_pass__(self):
        info("Performing First Analysis Pass (FAP)")
        
        chunks = self.trace.getChunks()

        info("Creating %d composite types" % len(chunks))
        
        # For each of the chunks create a composite type
        for chunk in chunks:
            # Create a new composite type
            chunk.composite = self.typer.createCompositeType(chunk.chunk_size)
            
            # Create a default type that covers the whole composite, later it may 
            # be split into smaller types
            chunk_type = self.typer.getType(chunk.chunk_size)
            
            # Add the type to the composite
            chunk.composite.addType(0, chunk_type)
            
            self.composite_types.add(chunk.composite)

            # List of the types discovered, not composites.
            self.infered_types.append(chunk_type)
            
            debug("Created composite type %s" % (chunk.composite.name))

        # For each method we detected
        for function in self.trace.getFunctions():
            debug("Analyzing function 0x%x" % function.ins_addr)
            
            # We need to skip potential destructors because they receive any kind of object and will mark them as the same type
            if function.ins_addr in self.trace.getDestructors():
                debug("Skipping destructor at %x" % function.ins_addr)                
                continue
            
            # Get all the chunks that were passed as this to the function.
            chunk_uses = function.getChunkUses()
            
            debug("Function has been executed %d times" % (len(chunk_uses)))
            
            for chunk_use in chunk_uses:
                chunk = chunk_use.chunk

                # Each chunk has its composite type reference.
                debug("Analyzing composite type %s" % (chunk.composite.name))
                
                # If the chunk use offset falls into the middle of a type, then split.
                if chunk.composite.shouldSplit(chunk_use.offset):
                    # Retrieve the previous type and offset
                    (offset, type_) = chunk.composite.getTypeAndOffsetAtOffset(chunk_use.offset)
                    
                    # Calculate the size of the previous type.
                    size_ = chunk_use.offset - offset
                    
                    # Check for invalid state.
                    if type_.size <= 0:
                        raise Exception("Error while trying to split type. New type size is zero")
                    
                    # We are splitting 'type_' into two types.
                    type_.size = size_
                                        
                    debug("Splitting type %s in two and adding a new type" % (type_.name))

                    # Get the next valid type offset greater than chunk.offset.
                    nearest_type_offset = chunk.composite.getNextTypeOffset(chunk_use.offset)
                                        
                    # The chunk does not have a type create a new one.
                    size_ = nearest_type_offset - chunk_use.offset
                    if size_ <= 0:
                        raise Exception("Size of the new type is less or equal to zero")
                    
                    # Create a new type.
                    chunk_type = self.typer.getType(size_)
                    
                    debug("Added chunk name %s and size %d at offset %d" % (chunk_type.name, chunk_type.size, chunk_use.offset))
                    
                    # There was no type here since we split the previous type, so add the new type to the composite.
                    chunk.composite.addType(chunk_use.offset, chunk_type)
                                        
                    # Add it to the list of inferred types to be used in the second pass.
                    self.infered_types.append(chunk_type)
                    
                else:    
                    chunk_type = chunk.composite.getTypeAtOffset(chunk_use.offset)
                    
                    # If we do not have a type at that offset yet, create one
                    if not chunk_type:
                        """
                        There was no type at the given offset. Create a new one.
                        The newly created type will range from the offset until the next valid
                        type or the end of the composite type.
                        """
                        # Get the next valid type offset greater than chunk.offset
                        nearest_type_offset = chunk.composite.getNextTypeOffset(chunk_use.offset)
                                            
                        # The chunk does not have a type create a new one.
                        size_ = nearest_type_offset - chunk_use.offset
                        if size_ <= 0:
                            raise Exception("Error while creating a new type. Size is zero.")

                        chunk_type = self.typer.getType(size_)
                        
                        debug("Added chunk name %s and size %d at offset %d" % (chunk_type.name, chunk_type.size, chunk_use.offset))
                        
                        # Add the new type to the composite
                        chunk.composite.addType(chunk_use.offset, chunk_type)
                        debug("There was no chunk at %d, creating a new type, %s" % (chunk_use.offset, chunk_type.name))    
                        
                        # Add it to the list of inferred types for use in the second pass.
                        self.infered_types.append(chunk_type)                                        

                    # Each type that used the current method must be of the same type.
                    self.type_constraints.setdefault(function.ins_addr, set()).add(chunk_type)

                    # Add the current function as a new method to the type                    
                    chunk_type.addMethod(function.ins_addr)
                    debug("Adding method 0x%.8x to type %s" % (function.ins_addr, chunk_type.name))

        # Now create all the fields
        self.__analyze_memory_accesses__()

        # NOTE: I have no idea why, but for some reason, there are types with no
        # methods attached. I am pruning these here in order to make the analysis faster
        # but there should be no reason why they are empty.
        info("Number of inferred types before pruning, %d" % (len(self.infered_types)))
        
        not_empty = lambda type_: (len(type_.methods) != 0)
        good_types = filter(not_empty, self.infered_types)
        self.infered_types = good_types
        
        info("Number of inferred types after pruning, %d" % (len(self.infered_types)))
        
        info("Solving simple type constraints")
        
        prev_inferred_types = len(self.infered_types)
        info("Number of inferred types is %d" % (prev_inferred_types))
        
        # Merge those types that share the same size and function uses
        for funcea in self.type_constraints.keys():
            rva = self.resolver.get_rva(funcea)
            rebased_addr = rva + self.ida_db.get_image_base()
            
            debug("Function 0x%x - Number of types %d" % (rebased_addr, len(self.type_constraints[funcea])))
            size2type = {}
            
            # Collect all the types of the same size
            for type_ in self.type_constraints[funcea]:
                size2type.setdefault(type_.size, set()).add(type_)
            
            new_types = set()
            
            # Merge them
            for types_ in size2type.values():
                new_type = self.__merge_types__(types_)
                                
                # We have already removed the previous types from the inferred types, now add the new one
                self.infered_types.append(new_type)
                
                new_types.add(new_type)
              
            # Now we still have type constraints, but with the merged types 
            self.type_constraints[funcea] = new_types
        
        info("Merged type constraints and ended up with %d types, reduced the amount of types by %d types" % \
             (len(self.infered_types), prev_inferred_types - len(self.infered_types)))

        """
        info("Debug information")
        info("=" * 120) 
        
        confusing_types = 0
        for funcea, types in self.type_constraints.items():
            rva = self.resolver.get_rva(funcea)
            #address_name = self.ida_db.get_function_name(rva)
            rebased_addr = rva + self.ida_db.get_image_base()
            
            if len(types) > 1:
                confusing_types += len(types)
                
                info("Function 0x%x" % (rebased_addr))
                for type_ in types:
                    rebased_methods = sorted(map(lambda x: self.ida_db.get_image_base() + self.resolver.get_rva(x), type_.methods))
                    methods = ",".join(map(hex, rebased_methods))
                    info("  Type: name=%12s, size=%.4x, methods=%s", type_.name, type_.size, methods)

        info("Number of fucked up types %d" % (confusing_types))
        info("=" * 120)
        """
        
    def __test_vtables__(self, e1, e2):
        """
        Returns wheter we have compatible vtables, ie. if the vtables
        in type e1 match the offset and value of the vtables in type e2.
        """

        # Take the offset and value of the vtables into account to check if they are indeed the same.
        e1_vtables = map(lambda x: (x.offset, x.vtable), filter(lambda x: x.isVTable() == True, e1.getFields()))
        e2_vtables = map(lambda x: (x.offset, x.vtable), filter(lambda x: x.isVTable() == True, e2.getFields()))
        
        shared_vtables = set(e1_vtables) & set(e2_vtables)
        nshared_vtables = len(shared_vtables)
        n_e1_vtables = len(e1_vtables)
        n_e2_vtables = len(e2_vtables)

        # Do the types have common vtables?
        if nshared_vtables:
            # The strongest indication that the object is the same is that they share _all_ the vtables.
            if nshared_vtables == n_e1_vtables  and nshared_vtables == n_e2_vtables:
                return True            
        
        return False

    def __test_methods__(self, e1, e2):
        """
        Test if both types share a certain number of methods, hence indicating
        the possibility that both objects share the same type.
        """
        # Calculate the number of shared methods.
        shared_methods = e1.getMethods() & e2.getMethods()
        
        len_sm = len(shared_methods)
        
        if not len_sm:
            return False
        
        nmethtods_e1 = len(e1.getMethods())
        nmethtods_e2 = len(e2.getMethods())

        try:
            # This gives us the ammount of methods shared per type.
            # sim_idx_1 = (float(len_sm) / float(nmethtods_e1)) * 100.0  # I do not trust python
            # sim_idx_2 = (float(len_sm) / float(nmethtods_e2)) * 100.0  # ditto
            global_sim_idx = (2.0 * len_sm) / (nmethtods_e1 + nmethtods_e2) * 100.0
        except ZeroDivisionError:
            # sim_idx_1 = 0.0
            # sim_idx_2 = 0.0
            global_sim_idx = 0.0

        """
        # Print statistics
        if sim_idx_1 > 0.0 or sim_idx_2 > 0.0 or global_sim_idx > 0.0:
            info("  Similar Type Information")
            info("    Type names                             : %s and %s" %(e1.name, e2.name))
            info("    Number of shared methods               : %d" % len_sm)
            info("    Number of methods in type_1            : %d" % nmethtods_e1)
            info("    Number of methods in type_2            : %d" % nmethtods_e2)
            info("    Individual Similarity Index for type_1 : %f" % sim_idx_1)
            info("    Individual Similarity Index for type_2 : %f" % sim_idx_2)
            info("    Global     Similarity Index            : %f" % global_sim_idx)
            info("")
        """
        
        ret = False        
        if global_sim_idx >= self.settings["similarity_threshold"]:
            ret = True
        #else:
            #info("XXX These types might need manual intervention (%s, %s)" %(e1.name, e2.name))            
        
        #return len_sm != 0
        return ret
        
    def __second_pass__(self):
        """
        The second class is a bit more complex than the first pass.
        It aggressively merges all similar types. Similar types are
        those that share some common characteristics like, the same size, 
        they share a bunch of common methods, they share some vtables, etc.
        
        We calculate a similarity index and if a given threshold is passed 
        then the type is merged.
        
        Every chunk that was typed with the merged types is later modified
        according to the new type.
        """
    
        info("Performing Second Analysis Pass")
    
        # Now we are going to merge all the types that are similar
        similar_types = {}
        
        # Insert all the chunks that share the same size into the dictionary
        for type_ in self.infered_types:
            similar_types.setdefault(type_.size, set()).add(type_)

        for size, types in similar_types.items():
            if len(types) > 1:
                info("Types of size %d" % (size))
                for type_ in types:
                    rebased_methods = sorted(map(lambda x: self.ida_db.get_image_base() + self.resolver.get_rva(x), type_.methods))
                    methods = ",".join(map(hex, rebased_methods))
                    info("  Type: name=%12s, size=%.4x, methods=%s", type_.name, type_.size, methods)
        
        for size, types in similar_types.items():
            if len(types) < 2:
                continue
            
            info("Merging %d similar types of size 0x%.4x" % (len(types), size))
            
            # Initially we are working with the types we have detected. Later we will add the merged ones
            work_queue = list(types)
            n_merges = 0
            
            while len(work_queue) > 1:
                # Get a type and compare it to the rest of the items in the work-list
                cur_type = work_queue.pop()
                
                # Build a set of the types that will be merged
                to_merge = set()
                to_merge.add(cur_type)
                
                # Compare the types and see if they match our merge requirements
                for e in list(work_queue):
                    #  NOTE: removed -> or self.__test_vtables__(cur_type, e)
                    if self.__test_methods__(cur_type, e):
                        to_merge.add(e)
                        work_queue.remove(e)
                        n_merges += 1
                
                if len(to_merge) > 1:                        
                    new_type = self.__merge_types__(to_merge)
                    work_queue.append(new_type)
                    self.infered_types.append(new_type)
                    
                    """
                    info("  Merging")
                    for type_ in to_merge:
                        rebased_methods = sorted(map(lambda x: self.ida_db.get_image_base() + self.resolver.get_rva(x), type_.methods))
                        methods = ",".join(map(hex, rebased_methods))
                        info("    Type: name=%12s, size=%.4x, methods=%s", type_.name, type_.size, methods)
                    """
            
            info("  Number of merges %d" % (n_merges))
              
        info("*" * 120)
        # Now we are going to merge all the types that are similar
        similar_types = {}
        
        # Insert all the chunks that share the same size into the dictionary
        for type_ in self.infered_types:
            similar_types.setdefault(type_.size, set()).add(type_)
        
        for size, types in similar_types.items():
            info("Types of size %d" % (size))
            for type_ in types:
                rebased_methods = sorted(map(lambda x: self.ida_db.get_image_base() + self.resolver.get_rva(x), type_.methods))
                methods = ",".join(map(hex, rebased_methods))
                info("  Type: name=%12s, size=%.4x, methods=%s", type_.name, type_.size, methods)
            
        function2types = {}
        for function in self.trace.getFunctions():
            types = set()
            
            # Get a list of all the used chunks with offsets that passed through this funcion
            used_chunks = function.getChunkUses()
            
            # Get the types of those chunks
            types = set(map(lambda x: x.chunk.composite.getTypeAtOffset(x.offset), used_chunks))
            
            # Map function to types used
            function2types[function.ins_addr] = function2types
            
            if len(types) > 1:
                if len(types) != len(map(lambda x: x.size, types)):
                    info("Function 0x%.8x has %d types:" % (function.ins_addr, len(types)))                                        
                    for type_ in types:
                        info("  Type: %r" % (type_))

        return
                        
    def dump_type(self, type_):
        methods = type_.getMethods()
        fields = sorted(type_.getFields())
        
        print "// Methods for type %s of size %d" % (type_.name, type_.size)
        
        # Bail out on types with no fields
        if not len(type_.fields):
            print "struct %s\n{    char unknown[%d];\n};" % (type_.name, type_.size)
            return
                
        for method in methods:
            rva = self.resolver.get_rva(method)
            address = rva + self.ida_db.get_image_base()
            print "//   Method 0x%.8x -> %s" % (address, self.ida_db.get_address_name(rva))
            
        print "struct %s" % type_.name
        print "{"
        
        
        j = 0
        size_to_next = fields[0].offset
        if size_to_next:
            print "       char padding_%d[%d];" % (j, size_to_next)
            j += 1
                
        for i in xrange(0, len(fields)):
            cur_field = fields[i]
            
            try:
                next_field = fields[i + 1]
                next_field_offset = next_field.offset
            except IndexError:
                next_field_offset = type_.size
            
            print "  ", cur_field
            
            next_offset = cur_field.offset + cur_field.size
            
            if next_offset != next_field_offset:
                size_to_next = next_field_offset - next_offset
                if size_to_next < 0:
                    print "// INVALID TYPE"
                    print "};\n"
                    return
                
                print "       char padding_%d[%d];" % (j, size_to_next)
                j += 1 
        
        print "};\n"

                                                
    def dump_types(self):                
        info("Dumping inferred types")

        for type_ in self.infered_types:
            self.dump_type(type_)
            
    def debug(self):
        for function in self.trace.getFunctions():

            rva = self.resolver.get_rva(function.ins_addr)
            address_name = self.ida_db.get_function_name(rva)
            rebased_addr = rva + self.ida_db.get_image_base()
            
            print "\nFunction %x : %s" % (rebased_addr, address_name)        
            
            sizes = set(map(lambda x: x.chunk.chunk_size, function.chunks_used)) 
            offsets = set(map(lambda x: x.offset, function.chunks_used))
            
            print "  Sizes   : ", sizes
            print "  Offsets : ", offsets
             
            for chunk in function.chunks_used:
                print "    id:%.8d, size:%.8d, offset:%.8d" % (chunk.chunk.timestamp, chunk.chunk.chunk_size, chunk.offset)
    
    def __analyze_memory_accesses__(self):
        # For each chunk
        chunks = self.trace.getChunks()
        for chunk in chunks:
            # Get a list of all the memory writes to this chunk
            mem_writes = chunk.getWrites()
            
            if len(mem_writes) == 0:
                debug("XXX Chunk %d has no writes, why is this here?" % (chunk.timestamp))
                continue 
            
            """
            bytes_written = sum(map(lambda x: x[1], set(map(lambda x: (x.write_addr - x.chunk_addr, x.write_size), mem_writes))))
            info("Analyzing memory writes for composite %s of size = 0x%x" %(chunk.composite.name, chunk.composite.size))
            info("Number of memory writes to this composite : %d" % len(mem_writes))
            info("Bytes written to the chunk                : %x" % (bytes_written))
            info("Coverage percentage                       : %f" % ((float(bytes_written) / float(chunk.composite.size))* 100.0))
            info("")
            """
                       
            for write in mem_writes:
                # Check if the current write sets a vtable somewhere.
                vtable = None
                if self.resolver.isValidAddress(write.content):
                    vtable = write.content
                
                # Get the offset of the chunk inside the composite.
                write_offset = write.write_addr - write.chunk_addr
                
                # Get the real offset of this type
                (real_offset, chunk_type) = chunk.composite.getTypeAndOffsetAtOffset(write_offset)                
                if not chunk_type:
                    raise Exception("Could not get chunk from composite %s at offset 0x%x" % (chunk.composite.name, write_offset))

                field_offset = write_offset - real_offset
                field_size = write.write_size
                
                # Check if we already had a field at offset
                field = chunk_type.getField(field_offset, field_size)
                if field:
                    # If we had a type, add a possibly new concrete value
                    field.addValue(write.content)
                    
                    # If chunk_ref is not zero, then this write referenced a heap chunk.
                    if write.chunk_ref:
                        field.addReferencedChunk(write.chunk_ref)
                    
                    debug("  Adding value to field at offset = 0x%.4x , size = 0x%.4x" % (write_offset, write.write_size))
                else:
                    # We need to fix the field offset and make it relative to the type and not the chunk.
                    field = FieldType(field_size, field_offset, vtable, write, write.chunk_ref)
                    chunk_type.addField(field)
                    
                    debug("  Adding field to type %16s at offset = 0x%.4x , size = 0x%.4x" % (chunk_type.name, write_offset, write.write_size))
            
        
        # We need to fill the gaps in the composite type (if any).
        for composite in self.composite_types:
            # By the way we create composites, this should never happen.
            if composite.isComplete() == False:
                info("Incomplete composite, filling the gaps.")
                composite.fillGaps(self.typer)
    
    def __third_pass__(self):
        """
        This method will analyze composite types and try to join those
        types that share methods. Now the size is not taken care of since
        there may be some special objects that have internal buffers with
        differing sizes. That is the case of for example vectors or strings.
        Both contains meta-data and the data itself inside the object describing
        the class.
        """
        # This is a list of those object that do not share any methods with other types
        proper_types = set()
        
        # The list of types that may need to be merged
        improper_types = set()
        
        for i in xrange(0, len(self.infered_types)):
            type_ = self.infered_types[i]
            methods = set(type_.getMethods())
            
            proper = True
            for next_type in self.infered_types[i + 1:]:
                # If there is no overlap of methods this is a unique type
                if set(next_type.getMethods()) & methods:
                    improper_types.add(type_)
                    proper = False
                    break
            
            if proper:
                proper_types.add(type_)
                    
        info("Number of proper types %d" % (len(proper_types)))
        info("Number of improper types %d" % (len(improper_types)))
        
        if len(proper_types) + len(improper_types) != len(self.infered_types):
            info("ERROR")
        
        for type_ in improper_types:
            methods = type_.getMethods()
            
            info("  Methods for type %s of size %d" % (type_.name, type_.size))
            
            for method in methods:
                rva = self.resolver.get_rva(method)
                address = rva + self.ida_db.get_image_base()
                info("    Method 0x%.8x -> %s" % (address, self.ida_db.get_address_name(rva)))

        
        import sys
        sys.exit()
    
    def analyze(self):
        self.__purgue__()

        self.__first_pass__()
        
        self.__second_pass__()
        
        # I have yet to know why are there duplicates here.
        self.infered_types = list(set(self.infered_types))
        
        #self.__third_pass__()

        return
