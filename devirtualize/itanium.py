import idaapi
import idc

from .utils import *

class ItaniumTypeInfo(object):
    def __init__(self, ea):
        self.ea = ea
        self.parents = []

        # first entry is the vptr for the typeinfo
        ea, _ = get_address(ea)
        ea, self.nameptr = get_address(ea)
        self.name = idc.GetString(self.nameptr)

        # After the name is either the base class typeinfo pointer
        # (in the case of single inheritance), or an array of
        # typeinfos for each base (in multiple inheritance)
        _, baseaddr = get_address(ea)

        # Crude test for whether the address seems like a
        # plausible location for the baseclass typeinfo
        if in_same_segment(baseaddr, ea):
            self.parents = [ItaniumTypeInfo(baseaddr)]
            return

        # Either this is multiple inheritance or no inheritance
        flags = idaapi.get_32bit(ea)
        count = idaapi.get_32bit(ea + 4)
        ea += 8

        # Only valid '__flags' are 0, 1, and 2
        if flags not in [0, 1, 2]:
            return

        self.flags = flags
        for i in range(count):
            ea, baseaddr = get_address(ea)
            self.parents.append(ItaniumTypeInfo(baseaddr))

            # For now ignore the '__offset_flags'
            ea += TARGET_ADDRESS_SIZE

    @property
    def str_ea(self):
        return "{:02x}".format(self.ea)

class ItaniumSubVtable(object):
    def __init__(self, ea):
        self.ea = ea

        ea, baseoffset = get_address(ea)
        self.baseoffset = as_signed(baseoffset, TARGET_ADDRESS_SIZE)

        # Arbitrary bounds for offset size
        if self.baseoffset < -0xFFFFFF or self.baseoffset > 0xFFFFFF:
            raise ValueError("Invalid subtable address `0x{:02x}`".format(self.ea))

        ea, typeinfo = get_address(ea)
        self.typeinfo = None

        if typeinfo != 0:
            if not in_same_segment(typeinfo, self.ea):
                raise ValueError("Invalid subtable address `0x{:02x}`".format(self.ea))
            else:
                self.typeinfo = ItaniumTypeInfo(typeinfo)

        self.functions = []

        # The start of the function array
        self.functions_ea = ea

        while True:
            ea, func = get_address(ea)

            # The first two functions can be 0
            if not is_in_executable_segment(func):
                if func == 0 and all([f == 0 for f in self.functions]):
                    pass
                else:
                    break

            self.functions.append(func)

        # Because the first two functions can be zero, and the RTTI
        # pointer and base offset can also be zero, require at least
        # one function to not be zero (so blocks of zero don't match).
        if all([f == 0 for f in self.functions]):
            raise ValueError("Invalid subtable address `0x{:02x}`".format(self.ea))

        self.size = TARGET_ADDRESS_SIZE*(len(self.functions) + 2)

    @property
    def name(self):
        if self.typeinfo is None:
            return None
        return self.typeinfo.name

    @property
    def str_ea(self):
        return "{:02x}".format(self.ea)

class ItaniumVTable(object):
    def __init__(self, ea):
        self.ea = ea
        self.subtables = []

        prev_offset = None
        while True:
            try:
                subtable = ItaniumSubVtable(ea)
            except:
                break

            # Sanity check the offset
            if prev_offset is None and subtable.baseoffset != 0:
                break
            elif prev_offset is not None and subtable.baseoffset >= prev_offset:
                break

            prev_offset = subtable.baseoffset
            self.subtables.append(subtable)
            ea += subtable.size

        if not self.subtables:
            raise ValueError("Invalid vtable address `0x{:02x}`".format(self.ea))

    def _primary_table(self):
        return self.subtables[0]

    @property
    def typeinfo(self):
        return self._primary_table().typeinfo

    @property
    def size(self):
        return sum([s.size for s in self.subtables])

    @property
    def name(self):
        prim = self._primary_table()
        if prim.typeinfo is not None:
            return prim.name
        return None

    @property
    def str_ea(self):
        return "{:02x}".format(self.ea)
