''' This module defines the generic Type interface for different ABIs.
'''

import idaapi
import idautils
import idc
import pickle

from .utils import *

if VTABLE_ABI == "ITANIUM":
    from .itanium import ItaniumTypeInfo as TypeInfo
    from .itanium import ItaniumVTableGroup as VTableGroup
else:
    raise RuntimeError("Unsupported vtable ABI")
    # from .msvc import MSVCTypeInfo as TypeInfo
    # from .msvc import MSVCVtable as VTable


def tables_from_names():
    ''' Yields addresses of VtableGroups if binary is not stripped
    '''
    for n in idautils.Names():
        seg = idaapi.getseg(n[0])
        if seg is None or seg.type != idaapi.SEG_DATA:
            continue

        if is_vtable_name(n[1]) is True:
            yield n[0]

def tables_from_heuristics(require_rtti=False):
    ''' Yields addresses of VTableGroups found via heuristic methods
    '''
    for s in idautils.Segments():
        seg = idaapi.getseg(s)
        if seg is None:
            continue
        if seg.type != idaapi.SEG_DATA:
            continue

        ea = seg.startEA
        while ea < seg.endEA:
            try:
                table = VTableGroup(ea)
                if require_rtti is True and ea.typeinfo is not None:
                    yield ea
                elif require_rtti is False:
                    yield ea
                ea += table.size
            except:
                # Assume vtables are aligned
                ea += TARGET_ADDRESS_SIZE

def type_matching_typeinfo(types, typeinfo):
    ''' Get the type in ``types`` that is associated with ``typeinfo``.
    '''
    if typeinfo is None:
        return None
    for type in types:
        if type.typeinfo is None:
            continue
        if type.typeinfo.ea == typeinfo.ea:
            return type
    return None

def save_type_info():
    ''' Save the current state/relationships between types. This
    essentially 'saves' the Devirtualize plugin.
    '''
    netnode()["saved_types"] = pickle.dumps(Types())

def Types(regenerate=False):
    ''' Returns a memoized list of Type objects for this binary
    '''
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
                parents = parents_from_destructors(type.tablegroup)

            for p in parents:
                p.children.append(type)
                type.parents.append(p)

    if regenerate is False and "saved_types" in netnode() and Types.cache is None:
        Types.cache = pickle.loads(netnode()["saved_types"])

    elif regenerate is True or Types.cache is None:
        Types.cache = []
        for table_ea in tables_from_heuristics():
            tablegroup = VTableGroup(table_ea)

            existing_type = type_matching_typeinfo(Types.cache, tablegroup.typeinfo)
            if existing_type:
                existing_type.tablegroup = tablegroup
            else:
                Types.cache.append(Type(tablegroup, tablegroup.typeinfo))

            if tablegroup.typeinfo:
                add_parents(Types.cache, tablegroup.typeinfo)

        generate_type_relations(Types.cache)
        save_type_info()

    return Types.cache
Types.cache = None

def get_type_by_name(name):
    ''' Returns any type object matching ``name``
    '''
    for t in Types():
        if t.name == name:
            return t
    return None

def get_type_by_func(ea):
    ''' Returns a Type with ``ea`` in its vtable. If there are multiple
    such types, the least derived type is returned (or the 1st found, if
    the multiple types have no known inheritance relationship).
    '''
    res = None
    for t in Types():
        if t.tablegroup is None:
            continue
        for table in t.tablegroup.tables:
            for func in table.functions:
                if func == ea and (res is None or t.is_ancestor_of(res)):
                    res = t
    return res

def get_type_by_tinfo(tinfo):
    ''' Returns the Type that has a struct with the associated ``tinfo``
    '''
    while tinfo.remove_ptr_or_array():
        continue
    for t in Types():
        if t.tinfo == tinfo:
            return t
    return None

#TODO:
#  1. Consider inlined destructors (or children of abstract types)
#  2. Multiple inheritance
def parents_from_destructors(tablegroup):
    ''' Finds the direct parents of the Type associated with ``tablegroup`` by
    examining function calls in its destructor.
    '''
    def destructor_calls(tablegroup):
        from itertools import chain
        candidates = []

        if tablegroup is None:
            return []

        # For now just use the first table array
        primary_table = tablegroup.primary_table()

        # When debug symbols are present, the decompile will usually
        # refer to the function table as an offset from the start
        # of the vtable, so also allow references to that.
        references = chain(idautils.XrefsTo(primary_table.address_point),
                           idautils.XrefsTo(tablegroup.ea))

        for ref in references:
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
            if type.tablegroup is None:
                continue
            if func_ea in destructor_calls(type.tablegroup):
                return type
        return None

    class destructor_finder_t(idaapi.ctree_visitor_t):
        def __init__(self, ea):
            idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)

        def visit_expr(self, e):
            if e.op == idaapi.cot_call:
                # Destructors only take 1 arg
                if len(e.a) != 1:
                    return 0
                elif e.a[0].v is None or e.a[0].v.idx != 0:
                    return 0

                addr = e.x.obj_ea
                type = get_type_having_destructor(addr)
                if type is None:
                    return 0
                parents.append(type)
                return 0

            elif e.op == idaapi.cot_asg:
                pass

            return 0

        def leave_expr(self, e):
            if e.op == idaapi.cot_call:
                self.destructor_candidate = None


    #TODO: consider other candidates
    destructors = destructor_calls(tablegroup)

    if len(destructors) == 0:
        return []
    destructor = destructors[0]
    parents = []

    try:
        cfunc = idaapi.decompile(destructor);
    except idaapi.DecompilationFailure:
        return []

    iff = destructor_finder_t(destructor)
    iff.apply_to(cfunc.body, None)
    return parents

class Type(object):
    ''' This is the fundamental type in ``Devirtualize``. `Type` is a flexible
    representation of a type that existed during compilation. Such a type may be
    discovered via RTTI or the presence of a TableGroup.
    '''
    def __init__(self, tablegroup=None, typeinfo=None):
        if tablegroup is None and typeinfo is None:
            raise ValueError("Either 'tablegroup' or 'typeinfo' must be non-None")

        #: Handle to the TableGroup backing this type (if any)
        self.tablegroup = tablegroup

        #: Handle to the RTTI typeinfo for this type (if any)
        self.typeinfo = typeinfo

        #: A list of this type's parents in inheritance order
        self.parents = []

        #: A list of this type's children
        self.children = []
        self.struct = None

        if self.typeinfo is None:
            if self.tablegroup is not None:
                self._name = "type_{:02x}".format(self.tablegroup.ea)
            else:
                self._name = "type_{:02x}".format(id(self))
        else:
            if self.typeinfo.name is None:
                self._name = "type_{:02x}".format(self.typeinfo.ea)
            else:
                self._name = demangle(self.typeinfo.name)

    def __eq__(self, other):
        if self.tablegroup is not None:
            if other.tablegroup is None:
                return False
            return self.tablegroup.ea == other.tablegroup.ea
        else:
            if other.typeinfo is None:
                return False
            return self.typeinfo.ea == other.typeinfo.ea

    @property
    def ancestors(self):
        ''' A tree of the parent types for this type (and their parents, etc).

        For a heirarchy like this::

                    A   B
                     \ /
                      C   D
                       \ /
                        E

        E's ancestors will be the nested dictionaries::

                {
                  C: {
                    A: {},
                    B: {}
                  },
                  D: {}
                }

        .. warning::
           Remember that dictionary traversal is not ordered, so the first item
           in the ancestors dictionary is not necessarily the first parent in
           the parents list.
        '''
        ancestors = {}
        for p in self.parents:
            ancestors[p] = p.ancestors
        return ancestors

    def is_descendant_of(self, other):
        ''' Returns True if ``other`` is a direct or indirect parent of this Type.
        '''
        for p in self.parents:
            if p == other or p.is_descendant_of(other):
                return True
        return False

    @property
    def descendants(self):
        ''' A tree of the child types for this type (and their children, etc).

        For a heirarchy like this::

                         A
                        / \ 
                       B   C
                      /   / \ 
                     D   E   F

        A's descendants will be the nested dictionaries::

                {
                  B: {
                    D: {},
                  },
                  C: {
                    E: {},
                    F: {}
                  }
                }
        '''
        descendants = {}
        for c in self.children:
            descendants[c] = c.descendants
        return descendants

    def is_ancestor_of(self, other):
        ''' Returns True if ``other`` is a direct or indirect child of this Type.
        '''
        for c in self.children:
            if c == other or c.is_ancestor_of(other):
                return True
        return False

    @property
    def family(self):
        ''' The set of Types that are the direct/indirect children and parents
        of this Type, as well as the children and parents of those types, recursively.
        '''
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

    @property
    def tinfo(self):
        tinfo = idaapi.tinfo_t()
        tinfo.get_named_type(idaapi.cvar.idati, self.name)
        return tinfo

    def table_for_cast(self, parent):
        ''' Finds the table that would be used for virtual function
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

        if self.tablegroup is None:
            return None

        total, found = traverse_heirarchy(self, parent)
        if found is False:
            return None

        return self.tablegroup.tables[total]


    def build_struct(self):
        ''' Creates an IDA structure for this Type.
        '''
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
                #TODO: for non-itanium ABI, this may not be available
                #      when RTTI is disabled
                offset = self.tablegroup.tables[i].offset_to_top
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


def fixup_this_arg_types(cfunc):
    ''' Modifies a cfuncptr_t such that its first argument is a pointer
    to the Type that has this cfunc in its vtable (and is named 'this')
    '''
    # Don't do anything if the type has already been set
    if idc.GetType(cfunc.entry_ea) is not None:
        return

    t = get_type_by_func(cfunc.entry_ea)
    if t is None:
        return

    tinfo = t.tinfo
    tinfo.create_ptr(tinfo)

    #TODO: add missing this argument?
    if len(cfunc.arguments) == 0:
        return

    cfunc.arguments[0].set_lvar_type(tinfo)
    cfunc.arguments[0].name = "this"

    cfunc.get_func_type(tinfo)
    idaapi.set_tinfo2(cfunc.entry_ea, tinfo)

def build_types():
    sid = idc.AddStrucEx(-1, "_vfunc", 0)
    if sid != -1:
        sptr = idaapi.get_struc(sid)
        idaapi.set_struc_hidden(sptr, True)
    for t in Types():
        t.build_struct()
    save_type_info()
