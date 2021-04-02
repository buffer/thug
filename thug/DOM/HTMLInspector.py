#!/usr/bin/env python
#
# HTMLInspector.py
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA  02111-1307  USA

import os
import logging
import json

import bs4

log = logging.getLogger("Thug")


class HTMLInspector:
    def __init__(self):
        self.enabled = True

        conf_file = os.path.join(log.configuration_path, 'inspector.json')
        if not os.path.exists(conf_file): # pragma: no cover
            self.enabled = False
            return

        with open(conf_file) as fd:
            self.rules = json.load(fd)

    def run(self, html, parser = "html.parser"):
        if self.enabled and html:
            self.inspect(html, parser)

        return bs4.BeautifulSoup(html, parser)

    @property
    def inspect_url(self):
        return log.ThugLogging.url if log.ThugOpts.local else log.last_url

    def inspect(self, html, parser):
        soup     = bs4.BeautifulSoup(html, parser)
        modified = False

        for action in self.rules:
            for s in self.rules[action]:
                for p in soup.select(s):
                    m = getattr(p, action, None)
                    if m:
                        m()
                        modified = True

        if modified:
            try:
                snippet = str(soup)
            except Exception: # pragma: no cover
                return

            log.ThugLogging.add_behavior_warn(
                description = "[HTMLInspector] Detected potential code obfuscation",
                snippet     = snippet,
                method      = "HTMLInspector deobfuscation")

            log.HTMLClassifier.classify(self.inspect_url, snippet)
