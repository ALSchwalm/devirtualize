import idaapi
import idc
import idautils

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

def print_ast(ea):
    cfunc = idaapi.decompile(ea)
    printer = ast_printer_t()
    printer.apply_to_exprs(cfunc.body, None)
