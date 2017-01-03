import idaapi
import idc
import idautils

class TypeGraph(idaapi.GraphViewer):
    def __init__(self, type, relationship="ancestors"):
        idaapi.GraphViewer.__init__(self, "Type Graph for {} of {}".format(
            relationship, type.name))
        self.type = type

        if relationship.lower() not in ["ancestors", "descendants"]:
            raise ValueError("Invalid relationship: `{}`".format(relationship))
        self.relationship = relationship.lower()

    def OnRefresh(self):
        print("there")
        self.Clear()

        root_id = self.AddNode(self.type.name)

        if self.relationship == "ancestors":
            self._do_graph(root_id, self.type.ancestors)
        else:
            self._do_graph(root_id, self.type.descendants)

        return True

    def _do_graph(self, parent_id, types):
        for type, relatives in types.iteritems():
            print("Adding node {}".format(type.name))
            newnode_id = self.AddNode(type.name)

            if self.relationship == "ancestors":
                self.AddEdge(newnode_id, parent_id)
            else:
                self.AddEdge(parent_id, newnode_id)
            self._do_graph(newnode_id, relatives)

    def OnGetText(self, node_id):
        label = self[node_id]
        return label
