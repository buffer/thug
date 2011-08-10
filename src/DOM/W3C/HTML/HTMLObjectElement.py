#!/usr/bin/env python
from __future__ import with_statement

from HTMLElement import HTMLElement
from attr_property import attr_property

class HTMLObjectElement(HTMLElement):
    @property
    def form(self):
        pass

    code            = attr_property("code")
    align           = attr_property("align")
    archive         = attr_property("archive")
    border          = attr_property("border")
    codeBase        = attr_property("codebase")
    codeType        = attr_property("codetype")
    data            = attr_property("data")
    declare         = attr_property("declare", bool)
    height          = attr_property("height")
    hspace          = attr_property("hspace", long)
    name            = attr_property("name")
    standBy         = attr_property("standby")
    tabIndex        = attr_property("tabindex", long, default = 0)
    type            = attr_property("type")
    useMap          = attr_property("usemap")
    vspace          = attr_property("vspace", long)
    width           = attr_property("width")

    # Introduced in DOM Level 2
    @property
    def contentDocument(self):
        return self.doc if self.doc else None
