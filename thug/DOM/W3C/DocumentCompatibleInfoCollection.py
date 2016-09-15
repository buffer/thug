#!/usr/bin/env python


class DocumentCompatibleInfoCollection(object):
    """
    http://msdn.microsoft.com/en-us/library/hh826015(v=vs.85).aspx

    There are no standards that apply here. 
    """

    def __init__(self, doc, nodes):
        self.doc   = doc
        self.nodes = nodes

    def __len__(self):
        return self.length

    def __getitem__(self, key):
        try:
            return self.item(int(key))
        except ValueError:
            return None

    @property
    def length(self):
        return len(self.nodes)

    @property
    def constructor(self):
        return None

    def item(self, index):
        if index > self.length - 1:
            return None

        return self.nodes[index]
