import idaapi
import idc

INFO = idaapi.get_inf_structure()

#TODO: this may not be an exhaustive list
if INFO.filetype in [
        idaapi.f_EXE_old,
        idaapi.f_COM_old,
        idaapi.f_DRV,
        idaapi.f_PE,
        idaapi.f_EXE,
        idaapi.f_COM]:
    VTABLE_ABI = "MSVC"
else:
    VTABLE_ABI = "ITANIUM"

if INFO.is_64bit():
    TARGET_ADDRESS_SIZE = 8
elif INFO.is_32bit():
    TARGET_ADDRESS_SIZE = 4
else:
    raise RuntimeError("Platform is not 64 or 32 bit")

def get_address(ea):
    if TARGET_ADDRESS_SIZE == 8:
        res = idaapi.get_64bit(ea)
    elif TARGET_ADDRESS_SIZE == 4:
        res = idaapi.get_32bit(ea)
    else:
        raise RuntimeError("Platform is not 64 or 32 bit")
    return (ea + TARGET_ADDRESS_SIZE, res)


def is_in_executable_segment(ea):
    if idaapi.getseg(ea) is None:
        return False
    return idaapi.getseg(ea).perm & idaapi.SEGPERM_EXEC

def is_vtable_name(name):
    demangled = idc.Demangle(name, idc.GetLongPrm(idc.INF_LONG_DN))
    if demangled is not None and demangled.startswith("`vtable for"):
        return True
    return False

def in_same_segment(addr1, addr2):
    return (idaapi.getseg(addr1) is not None and
            idaapi.getseg(addr2) is not None and
            idaapi.getseg(addr1).startEA ==
            idaapi.getseg(addr2).startEA)

def as_signed(value, size):
    return idaapi.as_signed(value, size*8)

def demangle(name, strip_arg_types=False):
    def strip_args(name):
        if strip_arg_types is True:
            return name.split("(", 1)[0]
        else:
            return name

    demangled = idc.Demangle(name, idc.GetLongPrm(idc.INF_LONG_DN))
    if demangled is not None:
        return strip_args(demangled)

    # The names in RTTI are not mangled normally, so try prepending
    # the '_Z'
    demangled = idc.Demangle("_Z" + name, idc.GetLongPrm(idc.INF_LONG_DN))
    if demangled is not None:
        return strip_args(demangled)

    return strip_args(name)
