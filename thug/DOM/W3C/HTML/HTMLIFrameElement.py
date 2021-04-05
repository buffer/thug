#!/usr/bin/env python

import logging

import thug.DOM.W3C as W3C
from .HTMLElement import HTMLElement
from .attr_property import attr_property

log = logging.getLogger("Thug")


class HTMLIFrameElement(HTMLElement):
    align          = attr_property("align")
    frameBorder    = attr_property("frameborder")
    height         = attr_property("height")
    longDesc       = attr_property("longdesc")
    marginHeight   = attr_property("marginheight")
    marginWidth    = attr_property("marginwidth")
    name           = attr_property("name")
    referrerpolicy = attr_property("referrerpolicy")
    sandbox        = attr_property("sandbox")
    scrolling      = attr_property("scrolling")
    src            = attr_property("src")
    srcdoc         = attr_property("srcdoc")
    width          = attr_property("width")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
        self.document = W3C.w3c.getDOMImplementation()

    # Introduced in DOM Level 2
    @property
    def contentDocument(self):
        return self.doc if self.doc else None

    @property
    def contentWindow(self):
        # if self.id in log.ThugLogging.windows:
        #    return log.ThugLogging.windows[self.id]

        return getattr(self.doc, 'window', None) if self.doc else None
