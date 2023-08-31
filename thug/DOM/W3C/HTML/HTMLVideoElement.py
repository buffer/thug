#!/usr/bin/env python

import logging

from .HTMLMediaElement import HTMLMediaElement
from .attr_property import attr_property

log = logging.getLogger("Thug")


class HTMLVideoElement(HTMLMediaElement):
    width       = attr_property("width", int, default = 0)
    height      = attr_property("height", int, default = 0)
    videoWidth  = attr_property("videoWidth", int, default = 0)
    videoHeight = attr_property("videoHeight", int, default = 0)
    playsInline = attr_property("playsInline", bool, default = False)
    poster      = attr_property("poster", default = "")

    def __init__(self, doc, tag):
        HTMLMediaElement.__init__(self, doc, tag)
