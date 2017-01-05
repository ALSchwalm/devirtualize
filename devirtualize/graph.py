import idaapi
import idc
import idautils

from .type import get_type_by_tinfo

class OpenGraphHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.target_type = None

    def activate(self, ctx):
        g = TypeGraph(self.target_type)
        g.Show()
        return 1

    def update(self, ctx):
        if self.target_type is not None:
            return idaapi.AST_ENABLE
        else:
            return idaapi.AST_DISABLE

def register_actions():
    AncestorGraphHandler = OpenGraphHandler()

    def type_of_current_var(vdui):
        var = vdui.item.get_lvar()
        if var is None:
            return None
        return get_type_by_tinfo(var.type())

    def graph_callback(event, *args):
        if event == idaapi.hxe_curpos:
            vdui = args[0]
            type = type_of_current_var(vdui)
            AncestorGraphHandler.target_type = type
        elif event == idaapi.hxe_populating_popup:
            form, popup, vdui = args
            if AncestorGraphHandler.target_type is None:
                return 0
            action_desc = idaapi.action_desc_t(
                None,
                'Open Ancestor Type Graph',
                AncestorGraphHandler)
            idaapi.attach_dynamic_action_to_popup(form, popup, action_desc, None)
        return 0

    action_desc = idaapi.action_desc_t(
        'devirtualize:open_ancestor_type_graph',
        'Open Ancestor Type Graph',
        AncestorGraphHandler,
        None,
        'Open Ancestor Type Graph',
        199)

    idaapi.register_action(action_desc)

    idaapi.attach_action_to_menu(
        'View/Graphs/User xrefs char...',
        'devirtualize:open_ancestor_type_graph',
        idaapi.SETMENU_APP)

    idaapi.install_hexrays_callback(graph_callback)


class TypeGraph(idaapi.GraphViewer):
    def __init__(self, type, relationship="ancestors"):
        idaapi.GraphViewer.__init__(self, "Type Graph for {} of {}".format(
            relationship, type.name))
        self.type = type

        if relationship.lower() not in ["ancestors", "descendants"]:
            raise ValueError("Invalid relationship: `{}`".format(relationship))
        self.relationship = relationship.lower()

    def OnRefresh(self):
        self.Clear()

        root_id = self.AddNode(self.type.name)

        if self.relationship == "ancestors":
            self._do_graph(root_id, self.type.ancestors)
        else:
            self._do_graph(root_id, self.type.descendants)

        return True

    def _do_graph(self, parent_id, types):
        for type, relatives in types.iteritems():
            newnode_id = self.AddNode(type.name)

            if self.relationship == "ancestors":
                self.AddEdge(newnode_id, parent_id)
            else:
                self.AddEdge(parent_id, newnode_id)
            self._do_graph(newnode_id, relatives)

    def OnGetText(self, node_id):
        label = self[node_id]
        return label
