#!/usr/bin/env python

from .Node import Node


class Notation(Node):
    @property
    def publicId(self):
        pass

    @property
    def systemId(self):
        pass

    @property
    def nodeName(self):
        pass

    @property
    def nodeType(self):
        return Node.NOTATION_NODE

    @property
    def nodeValue(self):
        return None
