#!/usr/bin/env python

import logging
from .HTMLElement import HTMLElement
from .attr_property import attr_property

log = logging.getLogger("Thug")


class HTMLFrameElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    frameBorder     = attr_property("frameborder")
    longDesc        = attr_property("longdesc")
    marginHeight    = attr_property("marginheight")
    marginWidth     = attr_property("marginwidth")
    name            = attr_property("name")
    noResize        = attr_property("noresize", bool)
    scrolling       = attr_property("scrolling")
    src             = attr_property("src")

    # Introduced in DOM Level 2
    @property
    def contentDocument(self):
        return self.doc if self.doc else None

    @property
    def contentWindow(self):
        if self.id in log.ThugLogging.windows:
            return log.ThugLogging.windows[self.id]

        if self.doc is None:
            return None

        return getattr(self.doc, 'window', None)
