#!/usr/bin/env python

import logging
import time
import datetime
from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .compatibility import thug_long

log = logging.getLogger("Thug")

class HTMLAnchorElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    accessKey       = attr_property("accesskey")
    charset         = attr_property("charset")
    coords          = attr_property("coords")
    href            = attr_property("href")
    hreflang        = attr_property("hreflang")
    name            = attr_property("name")
    rel             = attr_property("rel")
    rev             = attr_property("rev")
    shape           = attr_property("shape")
    tabIndex        = attr_property("tabindex", thug_long)
    target          = attr_property("target")
    type            = attr_property("type")

    def blur(self):
        pass

    def focus(self):
        pass

    def click(self):
        now = datetime.datetime.now()
        self.tag['_clicked'] = time.mktime(now.timetuple())
        if self.href:
            log.DFT.follow_href(self.href)
