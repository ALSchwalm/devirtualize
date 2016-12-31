import idaapi
import idautils
import idc

from .utils import *
from .type import Types

def translate_vptr_references(cfunc):
    class vptr_translator_t(idaapi.ctree_visitor_t):
        def __init__(self):
            idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)

        def visit_expr(self, e):
            if e.op == idaapi.cot_call:
                print(e.ea)
            return 0

    translator = vptr_translator_t()
    translator.apply_to(cfunc.body, None)

def translator_callback(event, *args):
    if event == idaapi.hxe_maturity:
        cfunc, maturity = args
        if maturity == idaapi.CMAT_FINAL:
            translate_vptr_references(cfunc)
    return 0


def register_vptr_translator():
    idaapi.install_hexrays_callback(translator_callback)
