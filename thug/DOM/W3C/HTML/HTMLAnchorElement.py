#!/usr/bin/env python

import logging
import time
import datetime

from urllib.parse import urlparse

from .HTMLElement import HTMLElement
from .attr_property import attr_property

log = logging.getLogger("Thug")


class HTMLAnchorElement(HTMLElement):
    accessKey = attr_property("accesskey")
    charset   = attr_property("charset", default = "")
    coords    = attr_property("coords")
    href      = attr_property("href")
    hreflang  = attr_property("hreflang")
    name      = attr_property("name")
    rel       = attr_property("rel")
    rev       = attr_property("rev")
    shape     = attr_property("shape")
    tabIndex  = attr_property("tabindex", int)
    target    = attr_property("target")
    type      = attr_property("type")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    @property
    def protocol(self):
        if not self.href:
            return ":"

        o = urlparse(self.href)
        return "{}:".format(o.scheme) if o.scheme else ":"

    @property
    def host(self):
        if not self.href:
            return ""

        o = urlparse(self.href)
        return o.netloc if o.netloc else ""

    @property
    def hostname(self):
        if not self.href:
            return ""

        return self.host.split(":")[0]

    @property
    def port(self):
        if not self.host:
            return ""

        if ":" not in self.host:
            return ""

        return self.host.split(":")[1]

    def blur(self):
        pass

    def focus(self):
        pass

    def click(self):
        now = datetime.datetime.now()
        self.tag['_clicked'] = time.mktime(now.timetuple())
        if self.href:
            log.DFT.follow_href(self.href)
