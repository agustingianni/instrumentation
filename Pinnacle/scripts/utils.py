import os
import idaapi

IMG_LOAD_FNAME = "img_load.out"
TAINTED_REPS_FNAME = "tainted_rep_pfx.out"
INSTR_HIT_FNAME = "instr_hit.out"

def ask_for_input_dir():
    input_dir = idaapi.askstr(0, "pinnacle_results",
                                 "Directory containing Pinnacle results")
    
    if input_dir is None:
        idaapi.msg("You must specify an input directory\n")
        return -1
    else:
        if not os.path.exists(input_dir):
            idaapi.msg("%s does not exist\n" % input_dir)
            return -1
        elif not os.path.isdir(input_dir):
            idaapi.msg("%s is not a directory\n" % input_dir)
            return -1
        elif not os.access(input_dir, os.R_OK):
            idaapi.msg("Insufficient permissions to read %s\n" % \
                       input_dir)
            return -1
        else:
            idaapi.msg("Processing results from %s\n" % input_dir)
        
        return input_dir    