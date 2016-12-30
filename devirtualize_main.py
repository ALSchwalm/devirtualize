import sys
import idc
import idautils
import idaapi

class devirtualize_plugin_t(idaapi.plugin_t):
    flags = 0
    comment = "Devirtualize virtual functions"
    wanted_name = "Devirtualize"
    wanted_hotkey = "Alt-D"
    help = "The help string"

    def init(self):
        idaapi.msg('devirtualize_plugin:init\n')
        if not idaapi.init_hexrays_plugin():
            idaapi.msg('No decompiler. Skipping\n')
            return idaapi.PLUGIN_SKIP
        return idaapi.PLUGIN_OK

    def run(self, arg):
        import traceback
        idaapi.require('devirtualize')
        idaapi.require('devirtualize.netnode')
        node = devirtualize.netnode.Netnode("$ devirtualize")

        try:
            idaapi.require('devirtualize.type')
        except:
            idaapi.msg(traceback.format_exc())
        idaapi.msg('devirtualize_plugin:run\n')

    def term(self):
        pass

def PLUGIN_ENTRY():
    return devirtualize_plugin_t()
