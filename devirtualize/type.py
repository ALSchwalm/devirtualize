import idaapi
import idautils
import idc
import pickle

from .utils import *

if VTABLE_ABI == "ITANIUM":
    from .itanium import ItaniumTypeInfo as TypeInfo
    from .itanium import ItaniumVTable as VTable
else:
    raise RuntimeError("Unsupported vtable ABI")
    # from .msvc import MSVCTypeInfo as TypeInfo
    # from .msvc import MSVCVtable as VTable


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
                table = VTable(ea)
                if require_rtti is True and ea.typeinfo is not None:
                    yield ea
                elif require_rtti is False:
                    yield ea
                ea += table.size
            except:
                # Assume vtables are aligned
                ea += TARGET_ADDRESS_SIZE

def Vtables(regenerate=False):
    if regenerate is True or Vtables.cache is None:
        Vtables.cache = list([VTable(t) for t in tables_from_heuristics()])
    return Vtables.cache
Vtables.cache = None

def type_matching_typeinfo(types, typeinfo):
    if typeinfo is None:
        return None
    for type in types:
        if type.typeinfo.ea == typeinfo.ea:
            return type
    return None

def save_type_info():
    netnode()["saved_types"] = pickle.dumps(Types())

def Types(regenerate=False):
    def add_parents(types, typeinfo):
        for parent in typeinfo.parents:
            existing_type = type_matching_typeinfo(types, parent)
            if existing_type:
                continue
            else:
                types.append(Type(None, parent))
                add_parents(types, parent)

    def generate_type_relations(types):
        # Generate the type relationships
        for type in types:
            if type.typeinfo is not None:
                parents = [type_matching_typeinfo(types, p)
                           for p in type.typeinfo.parents]
            else:
                parents = parents_from_destructors(type.vtable)

            for p in parents:
                p.children.append(type)
                type.parents.append(p)

    if regenerate is True or ("saved_types" in netnode() and Types.cache is None):
        Types.cache = pickle.loads(netnode()["saved_types"])

    elif regenerate is True or Types.cache is None:
        Types.cache = []
        for table_ea in tables_from_heuristics():
            vtable = VTable(table_ea)

            existing_type = type_matching_typeinfo(Types.cache, vtable.typeinfo)
            if existing_type:
                existing_type.vtable = vtable
            else:
                Types.cache.append(Type(vtable, vtable.typeinfo))

            if vtable.typeinfo:
                add_parents(Types.cache, vtable.typeinfo)

        generate_type_relations(Types.cache)
        save_type_info()

    return Types.cache
Types.cache = None

def get_type_by_name(name):
    for t in Types():
        if t.name == name:
            return t
    return None

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

def get_type_having_destructor(func_ea):
    for type in Types():
        if type.vtable is None:
            continue
        if func_ea in destructor_calls(type.vtable):
            return type
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

                addr = e.x.obj_ea
                type = get_type_having_destructor(addr)
                if type is None:
                    return 0

                self.destructor_candidate = (e, type)
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

class Type(object):
    def __init__(self, vtable=None, typeinfo=None):
        if vtable is None and typeinfo is None:
            raise ValueError("Either 'vtable' or 'typeinfo' must be non-None")

        self.vtable = vtable
        self.typeinfo = typeinfo

        self.parents = []
        self.children = []
        self.struct = None

        if self.typeinfo is None:
            if self.vtable is not None:
                self._name = "type_{:02x}".format(self.vtable.ea)
            else:
                self._name = "type_{:02x}".format(id(self))
        else:
            if self.typeinfo.name is None:
                self._name = "type_{:02x}".format(self.typeinfo.ea)
            else:
                self._name = demangle(self.typeinfo.name)

    def __eq__(self, other):
        if self.vtable is not None:
            if other.vtable is None:
                return False
            return self.vtable.ea == other.vtable.ea
        else:
            if other.typeinfo is None:
                return False
            return self.typeinfo.ea == other.typeinfo.ea

    @property
    def ancestors(self):
        ancestors = {}
        for p in self.parents:
            ancestors[p] = p.ancestors
        return ancestors

    @property
    def descendants(self):
        descendants = {}
        for c in self.children:
            descendants[c] = c.descendants
        return descendants

    @property
    def family(self):
        #TODO: memoize this

        # There really shouldn't be loops in this topology,
        # but the user could add one, so lets just assume
        # they're allowed.
        open_set = set([self])
        closed_set = set([])

        while len(open_set) > 0:
            type = open_set.pop()
            closed_set.add(type)
            for c in type.children:
                if c not in closed_set:
                    open_set.add(c)
            for p in type.parents:
                if p not in closed_set:
                    open_set.add(p)
        return closed_set

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, newname):
        #TODO: rename struct
        self._name = newname

    def subtable_for_cast(self, parent):
        ''' Returns the subtable that would be used for virtual function
        lookups if this type was cast to 'parent'.
        '''
        def traverse_heirarchy(tree, target):
            if len(tree.parents) == 0:
                return (1, False)
            total = 0
            found = False
            for type in tree.parents:
                if type == target:
                    return (total, True)
                count, found = traverse_heirarchy(type, target)
                total += count
                if found is True:
                    break
            return (total, found)
        if self.vtable is None:
            return None

        total, found = traverse_heirarchy(self, parent)
        if found is False:
            return None

        return self.vtable.subtables[total]


    def build_struct(self):
        if self.struct is not None:
            return

        for p in self.parents:
            p.build_struct()

        self.struct = idc.AddStrucEx(-1, self.name, 0)

        if as_signed(self.struct, TARGET_ADDRESS_SIZE) == -1:
            raise RuntimeError("Unable to make struct `{}`".format(self.name))

        if TARGET_ADDRESS_SIZE == 8:
            mask = idc.FF_QWRD
        else:
            mask = idc.FF_DWRD

        # Only bases get the magic _vptr member
        if len(self.parents) == 0:
            idc.AddStrucMember(self.struct,
                               "_vptr",
                               0,
                               idc.FF_DATA|mask,
                               -1,
                               TARGET_ADDRESS_SIZE)
            idc.SetType(idc.GetMemberId(self.struct, 0),
                        "_vfunc**");

        for i, parent in enumerate(self.parents):
            try:
                offset = self.vtable.subtables[i].baseoffset
            except:
                break

            idc.AddStrucMember(self.struct,
                               "parent_{}".format(i),
                               -offset,
                               idc.FF_DATA,
                               -1,
                               idc.GetStrucSize(parent.struct))

            idc.SetType(idc.GetMemberId(self.struct, -offset),
                        parent.name);


    def __str__(self):
        return self.name

    def __repr__(self):
        return str(self)

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

def build_types():
    idc.AddStrucEx(-1, "_vfunc", 0)
    for t in Types():
        t.build_struct()
    save_type_info()

print([t.name for t in Types()])
build_types()
