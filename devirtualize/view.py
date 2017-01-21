import idaapi
import idautils
import idc

from .utils import *
from .type import get_type_by_name, fixup_this_arg_types

def translate_vptr_references(cfunc):
    ''' The real 'work' function of Devirtualize. This function takes a
    cfuncptr and devirtualizes calls.
    '''
    def set_obj_ea(expr, val):
        ''' This function is an unholy incantation. Every time it is called
        it is as if millions of voices cry out all at once and are suddenly
        silenced. But, for the time being, it is necessary. So here goes:

        In the IDA AST representation, function calls (cot_call) have one
        child for each argument, and an additional child for the 'object'
        doing the call. For normal function calls this child will be a
        cot_obj, but it will be a pointer for function pointer calls.

        We need to replace this child (it will be the x operand) in the
        virtual function calls with a cot_obj once we have resolved the
        function. This is a simple procedure in principle, we just create
        a new cexpr_t and set 'op', 'type', and 'obj_ea' to the necessary
        values. However the python API currently has no way to set the
        'obj_ea'. To work around this without the C++ API, we use ctypes
        to access the appropriate offset from the this pointer and modify
        the value directly. Obviously this will break if the layout of
        cexpr_t or its parents change (i.e., with 64bit builds), but it
        is the best we can do for now.
        '''
        from ctypes import POINTER, c_ulonglong, cast
        assert(expr.op == idaapi.cot_obj)
        c_ulonglong_p = POINTER(c_ulonglong)
        offset = TARGET_ADDRESS_SIZE + 12
        cast(int(expr.this)+offset, c_ulonglong_p).contents.value = val
        assert(expr.obj_ea == val)

    class vptr_translator_t(idaapi.ctree_visitor_t):
        ''' The translator converts the virtual function callsites in the
        ast into normal function calls. This process requires a few pieces
        of information:

        1. The virtual call location
        2. The type of the object
        3. The index of the vtable being accessed

        This information can be difficult to gather because, for example,
        the decompiler can choose to use an indexing operation (i.e., vptr[3])
        or addition (vptr + 24) to access the function pointer.
        '''
        def __init__(self):
            idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST|idaapi.CV_POST)
            self.reset()

        def reset(self):
            self.func = None
            self.index = None
            self.cast_type = None
            self.type = None
            self.viable = False

        def visit_expr(self, e):
            if e.op == idaapi.cot_call:
                self.reset()
                self.func = e

            elif e.op == idaapi.cot_memref:
                if e.type.dstr() == "_vfunc **":
                    self.viable = True
                    self.cast_type = e.x.type

            elif e.op == idaapi.cot_add:
                if (self.func is None or
                    self.index is not None or
                    self.type is not None):
                    self.reset()
                    return 0
                if e.y.op == idaapi.cot_num:
                    self.index = e.y.numval()
                else:
                    self.reset()

            elif e.op == idaapi.cot_var:
                if self.func is None:
                    self.reset()
                    return 0
                elif self.type is None:
                    self.type = e.type
                return 0

            return 0

        def leave_expr(self, e):
            if e.op == idaapi.cot_call:
                self.reset()
            elif self.func is not None and e.is_child_of(self.func):
                if (self.viable is False or
                    self.cast_type is None or
                    self.func is None or
                    self.type is None):
                    self.reset()
                    return 0
                else:
                    self.type.remove_ptr_or_array()
                    this_type = get_type_by_name(self.type.dstr())

                    cast_type = get_type_by_name(self.cast_type.dstr())
                    table = this_type.table_for_cast(cast_type)

                    if self.index is None:
                        self.index = 0

                    func = table.functions[self.index]

                    # Create a new cot_obj expression and fill it with
                    # the ea of the function. Also use the type of the
                    # function.
                    obj = idaapi.cexpr_t()
                    obj.op = idaapi.cot_obj
                    t = tinfo_for_ea(func)
                    if t is not None:
                        t.create_ptr(t)
                        obj.type = t

                        #FIXME: this is a quick fix to correct the number of
                        # args to agree with the function type. Type info is
                        # still not propagated correctly. This might be fixed
                        # by running the visitor at an earlier maturity, but
                        # it is more difficult to identify virtual calls at
                        # earlier stages.
                        self.func.a.resize(t.get_nargs())
                    else:
                        obj.type = self.func.x.type
                    set_obj_ea(obj, func)

                    # Replace the existing func object (the virtual function
                    # pointer) with the new cot_obj
                    obj.swap(self.func.x)
                    self.reset()
            return 0


    translator = vptr_translator_t()
    translator.apply_to_exprs(cfunc.body, None)

def translator_callback(event, *args):
    if event == idaapi.hxe_maturity:
        cfunc, maturity = args
        if maturity == idaapi.CMAT_BUILT:
            fixup_this_arg_types(cfunc)
        elif maturity == idaapi.CMAT_FINAL:
            translate_vptr_references(cfunc)
    return 0


def register_vptr_translator():
    idaapi.install_hexrays_callback(translator_callback)
