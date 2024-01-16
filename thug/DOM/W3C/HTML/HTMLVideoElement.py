#!/usr/bin/env python

import logging

from .HTMLMediaElement import HTMLMediaElement
from .attr_property import attr_property
from .bool_property import bool_property

log = logging.getLogger("Thug")


class HTMLVideoElement(HTMLMediaElement):
    width = attr_property("width", int, default=0)
    height = attr_property("height", int, default=0)
    videoWidth = attr_property("videoWidth", int, default=0)
    videoHeight = attr_property("videoHeight", int, default=0)
    poster = attr_property("poster", default="")
    playsInline = bool_property("playsInline")

    def __init__(self, doc, tag):
        HTMLMediaElement.__init__(self, doc, tag)
