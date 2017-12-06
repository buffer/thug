#!/usr/bin/env python

import PyV8

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .compatibility import thug_long


class HTMLImageElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    align           = attr_property("align")
    alt             = attr_property("alt")
    border          = attr_property("border")
    height          = attr_property("height", thug_long)
    hspace          = attr_property("hspace", thug_long)
    isMap           = attr_property("ismap", bool)
    longDesc        = attr_property("longdesc")
    # Removed in DOM Level 2
    # lowSrc        = attr_property("lowsrc")
    name            = attr_property("name")
    # src           = attr_property("src")
    useMap          = attr_property("usemap")
    vspace          = attr_property("vspace", thug_long)
    width           = attr_property("width", thug_long)

    @property
    def complete(self):
        return True

    def getSrc(self):
        if 'src' in self.tag:
            return str(self.tag['src'])

        return None

    def setSrc(self, value):
        self.tag['src'] = str(value)

        if value.lower().startswith('res://'):
            onerror = getattr(self, 'onerror', None)

            if isinstance(onerror, PyV8.JSFunction):
                with self.doc.window.context as ctx:  # pylint:disable=unused-variable
                    onerror.__call__()

    src = property(getSrc, setSrc)
