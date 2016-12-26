import networkx as nx

try:
    import idaapi
    import idc
    import idautils
except ImportError:
    pass

from djgraph import DJGraph

def unroll_loops(cfg, g_start):
    # First check if we already have a DAG
    if nx.is_directed_acyclic_graph(cfg):
        return cfg

    tmp_cfg = nx.DiGraph(cfg)

    try:
        dj_graph = DJGraph(tmp_cfg, BasicBlockNode(g_start))
    except:
        print "codegraph::unroll_loops could not get DJGraph from from bb [%x : %x] skipping" % (g_start.startEA, g_start.endEA)
        print g_start

        raise

    for src, dst in dj_graph.get_sp_backedges_iter():
        tmp_cfg.remove_edge(src, dst)

    if not nx.is_directed_acyclic_graph(tmp_cfg):
        err = "Removing SP backedges did not result in DAG"
        raise Exception(err)

    return tmp_cfg

def get_function_cfg(func):
    # I do not trust idapython, so make sure we get the first actual basic block
    start_bb = get_func_head_bb(func)
    if not start_bb:
        raise Exception("Function at 0x%.8x has no start basic block that matches with func.startEA" % func.startEA)

    return get_controlflow_graph(start_bb)

def get_controlflow_graph(start_bb):
    dg = nx.DiGraph()

    work_list = [start_bb]
    processed_bbs = set()   

    # Export all the basic blocks
    while len(work_list) > 0:
        curr_bb = work_list.pop()
        dg.add_node(BasicBlockNode(curr_bb))

        for next_bb in curr_bb.succs():
            # print "Adding CFG edge from 0x%.8x to 0x%.8x" % (curr_bb.startEA, next_bb.startEA)

            dg.add_edge(BasicBlockNode(curr_bb), BasicBlockNode(next_bb))

            if next_bb.id not in processed_bbs:
                work_list.append(next_bb)
                processed_bbs.add(next_bb.id)

    return dg

def get_func_head_bb(func):
    basic_blocks = [bb for bb in idaapi.FlowChart(func)]

    res = filter(lambda x: x.startEA == func.startEA, basic_blocks)
    if not len(res):
        return 0

    return res[0]

class BasicBlockNode:
    def __init__(self, bb):
        self.bb = bb

    def __eq__(self, other):
        if other == None:
            return False

        return self.bb.startEA == other.bb.startEA

    def __hash__(self):
        return self.bb.startEA

def get_bb_instructions(bb):
    return filter(lambda head: idc.isCode(idc.GetFlags(head)), idautils.Heads(bb.startEA, bb.endEA))

def filter_by_mnem(instructions, mnem):
    return filter(lambda ins: idc.GetMnem(ins) == mnem, instructions)

def present_in_str(string_, list_of_strings):
    for this in list_of_strings:
        if this in string_:
            return True

    return False

CCONV_STDCALL = 0
CCONV_CDECL = 1
CCONV_THISCALL = 2
CCONV_INVALID = -1

def guess_calling_conv(func):
    start_bb = get_func_head_bb(func)
    if not start_bb:
        return CCONV_INVALID

    cfg = get_function_cfg(func)
    normalized_cfg = unroll_loops(cfg, start_bb)

    # Order is important, thiscall is also stdcall
    if is_thiscall(normalized_cfg):
        return CCONV_THISCALL
    elif is_stdcall(normalized_cfg):
        return CCONV_STDCALL

    return CCONV_CDECL

def is_stdcall(normalized_cfg):
    for bb in normalized_cfg:
        # Get the last instruction
        instructions = get_bb_instructions(bb.bb)
        if not len(instructions):
            print "codegraph::is_stdcall Failed to get instructions from bb [%x : %x] skipping" % (bb.bb.startEA, bb.bb.endEA)
            continue

        last_ins = instructions[-1]
        if idc.GetMnem(last_ins) == "retn":
            return len(idc.GetDisasm(last_ins).split()) > 1

def is_thiscall(normalized_cfg):
    bbs = nx.topological_sort(normalized_cfg)

    _is_thiscall = False
    this_regs = set(["ecx"])

    for bb in bbs:
        for ins_ea in get_bb_instructions(bb.bb):
            if _is_thiscall:
                return True
            
            mnem = idc.GetMnem(ins_ea)

            if mnem == "xor":
                op0_type = idc.GetOpType(ins_ea, 0)
                op1_type = idc.GetOpType(ins_ea, 1)
    
                if op0_type == idc.o_reg:
                    op0 = idc.GetOpnd(ins_ea, 0)
                    if op0 in this_regs:
                        this_regs.remove(op0)

                if op1_type == idc.o_reg:
                    op1 = idc.GetOpnd(ins_ea, 1)
                    if op1 in this_regs:
                        this_regs.remove(op1)

            elif mnem in ["dec", "inc"]:
                op0_type = idc.GetOpType(ins_ea, 0)                
                if op0_type == idc.o_reg:
                    op0 = idc.GetOpnd(ins_ea, 0)
                    if op0 in this_regs:
                        this_regs.remove(op0)

            elif mnem == "pop":
                # pop reg kills thisptrs too and is usual
                op0_type = idc.GetOpType(ins_ea, 0)
                if op0_type == idc.o_reg:
                    op0 = idc.GetOpnd(ins_ea, 0)
                    if present_in_str(op0, this_regs):
                        # print "    Instruction at %.8x POPPED 'thisptr' (%s)" % (ins_ea, idc.GetDisasm(ins_ea))
                        this_regs.remove(op0)

            elif mnem == "lea":
                op0 = idc.GetOpnd(ins_ea, 0)
                op1 = idc.GetOpnd(ins_ea, 1)

                op0_type = idc.GetOpType(ins_ea, 0)
                op1_type = idc.GetOpType(ins_ea, 1)

                if op0_type == idc.o_reg:
                    # Kill this registers if something is moved into it
                    if op0 in this_regs:
                        # If we are killing a this reg with a reference to the inside of an object, this is not a kill
                        uses_this = present_in_str(op1, this_regs)
                        if uses_this and not _is_thiscall:
                            print "    Instruction at %.8x REPLACED 'thisptr' (%s)" % (ins_ea, idc.GetDisasm(ins_ea))
                            _is_thiscall = True
                        else:
                            print "    Instruction at %.8x KILLED 'thisptr' (%s)" % (ins_ea, idc.GetDisasm(ins_ea))
                            this_regs.remove(op0)
    
                            # if we run out of this registers, bail out
                            if not len(this_regs) and not _is_thiscall:
                                return False

                    # Copy from thisreg into another register to replace the this pointer
                    if op1_type == idc.o_reg:
                        if op1 in this_regs:
                            print "    Instruction at %.8x ALIASED 'thisptr' (%s)" % (ins_ea, idc.GetDisasm(ins_ea))
                            this_regs.add(op0)

                    elif op1_type in [idc.o_mem, idc.o_phrase, idc.o_displ]:
                        uses_this = present_in_str(op1, this_regs)
                        if uses_this:
                            print "    Instruction at %.8x USES 'thisptr' (%s)" % (ins_ea, idc.GetDisasm(ins_ea))
                            _is_thiscall = True

                elif op0_type in [idc.o_mem, idc.o_phrase, idc.o_displ]:
                    uses_this = present_in_str(op0, this_regs)
                    if uses_this:
                        print "    Instruction at %.8x USES 'thisptr' (%s)" % (ins_ea, idc.GetDisasm(ins_ea))
                        _is_thiscall = True

            elif mnem == "mov":
                op0 = idc.GetOpnd(ins_ea, 0)
                op1 = idc.GetOpnd(ins_ea, 1)

                op0_type = idc.GetOpType(ins_ea, 0)
                op1_type = idc.GetOpType(ins_ea, 1)

                if op0_type == idc.o_reg:
                    # Kill this registers if something is moved into it
                    if op0 in this_regs:
                        # If we are killing a this reg with a reference to the inside of an object, this is not a kill
                        uses_this = present_in_str(op1, this_regs)
                        if uses_this and not _is_thiscall:
                            # print "    Instruction at %.8x REPLACED 'thisptr' (%s)" % (ins_ea, idc.GetDisasm(ins_ea))
                            _is_thiscall = True
                        else:
                            # print "    Instruction at %.8x KILLED 'thisptr' (%s)" % (ins_ea, idc.GetDisasm(ins_ea))
                            this_regs.remove(op0)
    
                            # if we run out of this registers, bail out
                            if not len(this_regs) and not _is_thiscall:
                                return False

                    # Copy from thisreg into another register to replace the this pointer
                    if op1_type == idc.o_reg:
                        if op1 in this_regs:
                            # print "    Instruction at %.8x ALIASED 'thisptr' (%s)" % (ins_ea, idc.GetDisasm(ins_ea))
                            this_regs.add(op0)

                    elif op1_type in [idc.o_mem, idc.o_phrase, idc.o_displ]:
                        uses_this = present_in_str(op1, this_regs)
                        if uses_this:
                            # print "    Instruction at %.8x USES 'thisptr' (%s)" % (ins_ea, idc.GetDisasm(ins_ea))
                            _is_thiscall = True

                elif op0_type in [idc.o_mem, idc.o_phrase, idc.o_displ]:
                    uses_this = present_in_str(op0, this_regs)
                    if uses_this:
                        # print "    Instruction at %.8x USES 'thisptr' (%s)" % (ins_ea, idc.GetDisasm(ins_ea))
                        _is_thiscall = True
            else:
                # Generic instruction 
                op0 = idc.GetOpnd(ins_ea, 0)
                op1 = idc.GetOpnd(ins_ea, 1)

                op0_type = idc.GetOpType(ins_ea, 0)
                op1_type = idc.GetOpType(ins_ea, 1)
                
                if op0_type in [idc.o_mem, idc.o_phrase, idc.o_displ]:
                    uses_this = present_in_str(op0, this_regs)
                    if uses_this:
                        # print "    Instruction at %.8x USES 'thisptr' (%s)" % (ins_ea, idc.GetDisasm(ins_ea))
                        _is_thiscall = True
                
                if op1_type in [idc.o_mem, idc.o_phrase, idc.o_displ]:
                    uses_this = present_in_str(op1, this_regs)
                    if uses_this:
                        # print "    Instruction at %.8x USES 'thisptr' (%s)" % (ins_ea, idc.GetDisasm(ins_ea))
                        _is_thiscall = True

    return _is_thiscall

"""
funcea = 0x01005987
func = idaapi.get_func(funcea)
cconv = guess_calling_conv(func)
if cconv == CCONV_CDECL:
    print " %.8x - CDECL" % (funcea)
elif cconv == CCONV_STDCALL:
    print " %.8x - STDCALL" % (funcea)
elif cconv == CCONV_THISCALL:
    print " %.8x - THISCALL" % (funcea)
"""

"""
for funcea in idautils.Functions():
    func = idaapi.get_func(funcea)

    cconv = guess_calling_conv(func)
    
    if cconv == CCONV_CDECL:
        print " %.8x - CDECL" % (funcea)
    elif cconv == CCONV_STDCALL:
        print " %.8x - STDCALL" % (funcea)
    elif cconv == CCONV_THISCALL:
        print " %.8x - THISCALL" % (funcea)
"""

"""
s1 = set()
s2 = set()

for funcea in idautils.Functions():
    func = idaapi.get_func(funcea)
    cconv = guess_calling_conv(func, False)
    if cconv == CCONV_THISCALL:
        s1.add(funcea)

for funcea in idautils.Functions():
    func = idaapi.get_func(funcea)
    cconv = guess_calling_conv(func, True)
    if cconv == CCONV_THISCALL:
        s2.add(funcea)
        
print len(s1)
print len(s2)

print "Those in s1 but not in s2"
for a in (s1 - (s1 & s2)):
    print "0x%.8x" % a

print "-"*80

print "Those in s2 but not in s1"
for a in (s2 - (s1 & s2)):
    print "0x%.8x" % a
"""