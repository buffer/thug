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

    # Introduced in DOM Level 3
    @property
    def textContent(self):
        return None
