#!/usr/bin/env python

import string
import logging
from .HTMLElement import HTMLElement

log = logging.getLogger("Thug")


class TAnimateColor(HTMLElement):
    def __init__(self, doc, tag):
        self.doc = doc
        self.tag = tag
        HTMLElement.__init__(self, doc, tag)

        self._values = ""

    def get_values(self):
        return self._values

    def set_values(self, values):
        if all(c in string.printable for c in values) is False:
            log.ThugLogging.log_exploit_event(self.doc.window.url,
                                              "Microsoft Internet Explorer",
                                              "Microsoft Internet Explorer CButton Object Use-After-Free Vulnerability (CVE-2012-4792)",
                                              cve = 'CVE-2012-4792',
                                              forward = True)

            log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2012-4792", None)

        log.DFT.check_shellcode(values)
        self._values = values

    values = property(get_values, set_values)
