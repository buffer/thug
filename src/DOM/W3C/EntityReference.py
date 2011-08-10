#!/usr/bin/env python
from __future__ import with_statement

from DOMException import DOMException
from Node import Node
from Events import *


class EntityReference(Node):
    def __init__(self, doc, name):
        Node.__init__(self, doc)

        self.name = name

    def nodeName(self):
        return self.name

