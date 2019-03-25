#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .form_property import form_property


class HTMLLabelElement(HTMLElement):
    accessKey = attr_property("accesskey")
    form      = form_property()
    htmlFor   = attr_property("for")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
