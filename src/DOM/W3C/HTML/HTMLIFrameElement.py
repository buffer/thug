#!/usr/bin/env python

from HTMLElement import HTMLElement
from attr_property import attr_property

class HTMLIFrameElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    align           = attr_property("align")
    frameBorder     = attr_property("frameborder")
    height          = attr_property("height")
    longDesc        = attr_property("longdesc")
    marginHeight    = attr_property("marginheight")
    marginWidth     = attr_property("marginwidth")
    name            = attr_property("name")
    scrolling       = attr_property("scrolling")
    src             = attr_property("src")
    width           = attr_property("width")

    # Introduced in DOM Level 2
    @property
    def contentDocument(self):
        return self.doc if self.doc else None

