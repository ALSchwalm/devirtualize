import idaapi
import idautils
import idc

info = idaapi.get_inf_structure()
if info.is_64bit():
    TARGET_ADDRESS_SIZE = 8
elif info.is_32bit():
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
    if value > 1 << (size*8 - 1):
        return value - (1 << (size*8))
    else:
        return value

def tables_from_names():
    for n in idautils.Names():
        seg = idaapi.getseg(n[0])
        if seg is None or seg.type != idaapi.SEG_DATA:
            continue

        if is_vtable_name(n[1]) is True:
            yield n[0]

def tables_from_heuristics(require_rtti=False):
    for s in idautils.Segments():
        seg = idaapi.getseg(s)
        if seg is None:
            continue
        if seg.type != idaapi.SEG_DATA:
            continue

        ea = seg.startEA
        while ea < seg.endEA:
            try:
                table = ItaniumVTable(ea)
                if require_rtti is True and ea.typeinfo is not None:
                    yield ea
                elif require_rtti is False:
                    yield ea
                ea += table.size
            except:
                ea += TARGET_ADDRESS_SIZE

def Vtables(regenerate=False):
    if regenerate is True or Vtables.cache is None:
        Vtables.cache = list([ItaniumVTable(t) for t in tables_from_heuristics()])
    return Vtables.cache
Vtables.cache = None

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
            ea += 8

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
        return "type_{:02x}".format(self.ea)

def table_from_typeinfo(typeinfo, tables):
    for candidate in tables:
        if candidate.typeinfo is None:
            continue
        elif candidate.typeinfo.ea == typeinfo.ea:
            return candidate
    return None

def find_hierarchy_with_rtti(vtable):
    def find_hierarchy_with_typeinfo(typeinfo):
        if typeinfo is None:
            return {}
        hierarchy = {}

        for parent in typeinfo.parents:
            hierarchy[parent.name] = find_hierarchy_with_typeinfo(parent)
        return hierarchy
    return find_hierarchy_with_typeinfo(vtable.typeinfo)

def destructor_calls(vtable):
    candidates = []

    # For now just use the first subtable array
    primary_table = vtable.subtables[0]

    for ref in idautils.XrefsTo(primary_table.functions_ea):
        start = as_signed(idc.GetFunctionAttr(ref.frm, idc.FUNCATTR_START),
                          TARGET_ADDRESS_SIZE)
        if start == -1:
            continue
        candidates.append(start)

    #TODO: don't assume the destructor is virtual
    candidates = [c for c in candidates if c in primary_table.functions]
    return candidates

def get_table_having_destructor(func_ea):
    for table in Vtables():
        if func_ea in destructor_calls(table):
            return table
    return None


def parents_from_destructors(vtable):
    #TODO: consider other candidates
    destructor = destructor_calls(vtable)[0]

    parents = []
    cfunc = idaapi.decompile(destructor);

    class destructor_finder_t(idaapi.ctree_visitor_t):
        def __init__(self, ea):
            idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
            self.destructor_candidate = None

        def visit_expr(self, e):
            if e.op == idaapi.cot_call:
                # Destructors only take 1 arg
                if len(e.a) != 1:
                    return 0

                # Strange two-step to get the address of the
                # function being called by this expression.
                #
                # If anyone has a better way to do this, please
                # let me know.
                func_name = idc.GetOpnd(e.ea, 0)
                addr = idaapi.get_name_ea(idc.BADADDR, func_name)

                table = get_table_having_destructor(addr)
                if table is None:
                    return 0

                self.destructor_candidate = (e, table)
                return 0
            elif e.op == idaapi.cot_var:
                if (self.destructor_candidate is None or
                    not e.is_call_arg_of(self.destructor_candidate[0]) or
                    e.v.idx != 0):
                    return 0
                parents.append(self.destructor_candidate[1])
            return 0

        def leave_expr(self, e):
            if e.op == idaapi.cot_call:
                self.destructor_candidate = None


    iff = destructor_finder_t(destructor)
    iff.apply_to(cfunc.body, None)
    return parents

def func_type_ptr(cfunc):
    tinfo = idaapi.tinfo_t()
    cfunc.get_func_type(tinfo)
    tinfo.create_ptr(tinfo)
    return tinfo.dstr()

def fixup_this_type(cfunc, func_addr, this_type):
    tinfo = idaapi.tinfo_t()
    tinfo.get_named_type(idaapi.cvar.idati, this_type)
    tinfo.create_ptr(tinfo)

    #TODO: add missing this argument
    if len(cfunc.arguments) == 0:
        return

    cfunc.arguments[0].set_lvar_type(tinfo)
    cfunc.arguments[0].name = "this"

    cfunc.get_func_type(tinfo)
    idaapi.set_tinfo2(func_addr, tinfo)


def create_types():
    for table in Vtables():
        struct_name = table.name
        struct_id = idc.AddStrucEx(-1, struct_name, 0)

        if TARGET_ADDRESS_SIZE == 8:
            mask = idc.FF_QWRD
        else:
            mask = idc.FF_DWRD

        for i, subtable in enumerate(table.subtables):
            if table.name is not None:
                vtable_name = "subtable{}_{}".format(struct_name, i)
            else:
                vtable_name = "subtable_{:02x}_{}".format(table.ea, i)

            subtable_id = idc.AddStrucEx(-1, vtable_name, 0)

            for n, func in enumerate(subtable.functions):
                idc.AddStrucMember(subtable_id,
                                   idc.GetFunctionName(func),
                                   -1,
                                   idc.FF_DATA|mask,
                                   -1,
                                   TARGET_ADDRESS_SIZE)
                cfunc = idaapi.decompile(func)
                fixup_this_type(cfunc, func, struct_name)
                ptr = func_type_ptr(cfunc)
                idc.SetType(idc.GetMemberId(subtable_id, n*TARGET_ADDRESS_SIZE),
                            ptr)

            idc.AddStrucMember(struct_id,
                               "_vptr_{}".format(i),
                               -subtable.baseoffset,
                               idc.FF_DATA|mask,
                               -1,
                               TARGET_ADDRESS_SIZE)

            idc.SetType(idc.GetMemberId(struct_id, -subtable.baseoffset),
                        vtable_name + "*");

def find_hierarchy_without_rtti(vtable):
    hierarchy = {}

    parents = parents_from_destructors(vtable)
    for parent in parents:
        hierarchy[parent.name] = find_hierarchy_without_rtti(parent)
    return hierarchy

create_types()

# print(parents_from_destructors(Vtables()[0]))

for table in Vtables():
    print(table.name, find_hierarchy_without_rtti(table))
