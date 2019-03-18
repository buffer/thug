#!/usr/bin/env python

import logging

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .compatibility import thug_long

log = logging.getLogger("Thug")


class HTMLImageElement(HTMLElement):
    align    = attr_property("align")
    alt      = attr_property("alt")
    border   = attr_property("border")
    height   = attr_property("height", thug_long)
    hspace   = attr_property("hspace", thug_long)
    isMap    = attr_property("ismap", bool)
    longDesc = attr_property("longdesc")
    name     = attr_property("name")
    useMap   = attr_property("usemap")
    vspace   = attr_property("vspace", thug_long)
    width    = attr_property("width", thug_long)

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    @property
    def complete(self):
        return True

    def getSrc(self):
        if 'src' in self.tag.attrs:
            return str(self.tag.attrs['src'])

        return None

    def setSrc(self, value):
        self.tag.attrs['src'] = str(value)

        if value.lower().startswith('res://'):
            onerror = getattr(self, 'onerror', None)

            if log.JSEngine.isJSFunction(onerror):
                with self.doc.window.context as ctx:  # pylint:disable=unused-variable
                    onerror.__call__()

    src = property(getSrc, setSrc)
