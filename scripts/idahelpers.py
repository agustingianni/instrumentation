import idc
import idaapi

def rgb_to_bgr(color):
    r = color >> 16
    g = color >> 8 & 0xff
    b = color & 0xff
    return (b << 16) | (g << 8) | r 

def SetFunctionColor(ea, MARKED_FUNC_COLOR):
    idc.SetColor(ea, idc.CIC_FUNC, rgb_to_bgr(MARKED_FUNC_COLOR))

def SetInstructionColor(ea, MARKED_INS_COLOR):
    idc.SetColor(ea, idc.CIC_ITEM, rgb_to_bgr(MARKED_INS_COLOR))
    
def SetBasicBlockColor(ea, MARKED_BASIC_BLOCK_COLOR):
    curr = ea

    done = False
    while curr != idaapi.BADADDR:
        if curr != ea:
            xb = idaapi.xrefblk_t()
            ok = xb.first_to(curr, idaapi.XREF_ALL)
            while ok and xb.iscode:
                if xb.type in [idaapi.fl_JF, idaapi.fl_JN]:
                    done = True
                    break

                ok = xb.next_to()

        if done:
            break

        SetInstructionColor(curr, MARKED_BASIC_BLOCK_COLOR)
        next = idaapi.BADADDR
        xb = idaapi.xrefblk_t()
        ok = xb.first_from(curr, idaapi.XREF_ALL)

        while ok and xb.iscode:
            if xb.type in [idaapi.fl_JF, idaapi.fl_JN]:
                done = True
                break
            elif xb.type == idaapi.fl_F:
                next = xb.to

            ok = xb.next_from()

        if done:
            break

        curr = next
