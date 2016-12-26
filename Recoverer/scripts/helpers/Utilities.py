'''
Created on Mar 17, 2012

@author: gr00vy
'''

def GetAddressName(address):
    from idc import GetTrueName, Demangle, GetLongPrm, INF_SHORT_DN
    
    addr_name = GetTrueName(address)
    name = Demangle(addr_name, GetLongPrm(INF_SHORT_DN))
    if name == None:
        if addr_name == None or addr_name == "":
            return "0x%.8x" % address
        
        name = addr_name
    
    return name

def GetImportedFunctionsNames():
    import idaapi

    names = []    
    def imp_cb(ea, name, ord):
        if name:
            names.append(name)

        # True -> Continue enumeration
        # False -> Stop enumeration
        return True
    
    nimps = idaapi.get_import_module_qty()
        
    for i in xrange(0, nimps):
        name = idaapi.get_import_module_name(i)
        if not name:
            continue
    
        idaapi.enum_import_names(i, imp_cb)
        
    return names