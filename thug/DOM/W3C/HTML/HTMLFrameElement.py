#!/usr/bin/env python

import logging
from .HTMLElement import HTMLElement
from .attr_property import attr_property

log = logging.getLogger("Thug")


class HTMLFrameElement(HTMLElement):
    frameBorder  = attr_property("frameborder")
    longDesc     = attr_property("longdesc")
    marginHeight = attr_property("marginheight")
    marginWidth  = attr_property("marginwidth")
    name         = attr_property("name")
    noResize     = attr_property("noresize", bool)
    scrolling    = attr_property("scrolling")
    src          = attr_property("src")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    # Introduced in DOM Level 2
    @property
    def contentDocument(self):
        return self.doc if self.doc else None

    @property
    def contentWindow(self):
        # if self.id in log.ThugLogging.windows:
        #    return log.ThugLogging.windows[self.id]

        return getattr(self.doc, 'window', None) if self.doc else None
