import idaapi
import idautils
import idc

from .utils import *
from .type import get_type_by_name

class ast_printer_t(idaapi.ctree_visitor_t):
    def __init__(self):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST|idaapi.CV_POST)
        self.level = 0
        self.nodes = [
            "cot_comma", "cot_asg", "cot_asgbor", "cot_asgxor", "cot_asgband",
            "cot_asgadd", "cot_asgsub", "cot_asgmul", "cot_asgsshr", "cot_asgushr",
            "cot_asgshl", "cot_asgsdiv", "cot_asgudiv", "cot_asgsmod", "cot_asgumod",
            "cot_tern", "cot_lor", "cot_land", "cot_bor", "cot_xor", "cot_band",
            "cot_eq", "cot_ne", "cot_sge", "cot_uge", "cot_sle", "cot_ule", "cot_sgt",
            "cot_ugt", "cot_slt", "cot_ult", "cot_sshr", "cot_ushr", "cot_shl",
            "cot_add", "cot_sub", "cot_mul", "cot_sdiv", "cot_udiv", "cot_smod",
            "cot_umod", "cot_fadd", "cot_fsub", "cot_fmul", "cot_fdiv", "cot_fneg",
            "cot_neg", "cot_cast", "cot_lnot", "cot_bnot", "cot_ptr", "cot_ref",
            "cot_postinc", "cot_postdec", "cot_preinc", "cot_predec", "cot_call",
            "cot_idx", "cot_memref", "cot_memptr", "cot_num", "cot_fnum", "cot_str",
            "cot_obj", "cot_var", "cot_insn", "cot_sizeof", "cot_helper", "cot_type"
        ]

    def visit_expr(self, e):
        for node in self.nodes:
            if e.op == idaapi.__dict__[node]:
                print((" " * self.level) + "{} at {:02x}".format(node, e.ea))
                self.level += 1
        return 0

    def leave_expr(self, e):
        for node in self.nodes:
            if e.op == idaapi.__dict__[node]:
                self.level -= 1
        return 0


def translate_vptr_references(cfunc):
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
                    subtable = this_type.subtable_for_cast(cast_type)

                    if self.index is None:
                        self.index = 0

                    func = subtable.functions[self.index]
                    name = demangle(idc.Name(func), strip_arg_types=True)

                    replacement = idaapi.call_helper(self.func.type,
                                                     self.func.a,
                                                     name)
                    replacement.ea = e.ea
                    self.func.replace_by(replacement)
                    self.reset()
            return 0


    translator = vptr_translator_t() # ast_printer_t()
    translator.apply_to(cfunc.body, None)

def translator_callback(event, *args):
    if event == idaapi.hxe_maturity:
        cfunc, maturity = args
        if maturity == idaapi.CMAT_FINAL:
            translate_vptr_references(cfunc)
    # elif event == idaapi.hxe_double_click:
    #     vu, shift_state = args

    return 0


def register_vptr_translator():
    idaapi.install_hexrays_callback(translator_callback)
