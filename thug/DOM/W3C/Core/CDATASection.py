#!/usr/bin/env python

from .Text import Text


class CDATASection(Text):
    @property
    def nodeName(self):
        return "#cdata-section"

    @property
    def nodeType(self):
        from .NodeType import NodeType

        return NodeType.CDATA_SECTION_NODE
