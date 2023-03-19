#!/usr/bin/env python
#
# Location.py
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

import logging
from urllib.parse import urlparse, urlunparse

from thug.DOM.W3C import w3c
from .JSClass import JSClass

log = logging.getLogger("Thug")


class Location(JSClass):
    def __init__(self, window):
        self._window = window

    def toString(self):
        return self._window.url

    @property
    def parts(self):
        return urlparse(self._window.url)

    @property
    def href(self):
        return self._window.url

    @href.setter
    def href(self, url):
        if url.startswith("data:"):
            log.DFT._handle_data_uri(url)
            return

        referer = self._window.url
        if log.HTTPSession.check_equal_urls(url, referer):
            log.warning("Skipping location redirection from %s to %s", referer, url)
            return

        for p in log.ThugOpts.Personality:
            if log.ThugOpts.Personality[p]['userAgent'] == self._window._navigator.userAgent:
                break

        url = log.HTTPSession.normalize_url(self._window, url)
        log.ThugLogging.log_href_redirect(referer, url)

        doc = w3c.parseString('')
        window = log.Window(referer, doc, personality=p)
        window = window.open(url)
        if not window:
            return

        from .DFT import DFT

        dft = DFT(window)
        dft.run()

    @property
    def protocol(self):
        return self.parts.scheme

    @protocol.setter
    def protocol(self, protocol):
        if protocol != self.parts.scheme:
            self.href = urlunparse(self.parts._replace(scheme=protocol))

    @property
    def host(self):
        return self.parts.netloc

    @host.setter
    def host(self, host):
        if host != self.parts.netloc:
            self.href = urlunparse(self.parts._replace(netloc=host))

    @property
    def hostname(self):
        return self.parts.hostname

    @hostname.setter
    def hostname(self, hostname):
        snetloc = self.parts.netloc.split(':')
        if len(snetloc) and hostname != snetloc[0]:
            host = f"{hostname}:{snetloc[1]}" if len(snetloc) > 1 else hostname
            self.host = host

    @property
    def port(self):
        return self.parts.port

    @port.setter
    def port(self, port):
        snetloc = self.parts.netloc.split(':')
        if len(snetloc) > 1 and str(port) != snetloc[1]:
            self.host = f"{snetloc[0]}:{port}"

    @property
    def pathname(self):
        return self.parts.path

    @pathname.setter
    def pathname(self, pathname):
        if pathname != self.parts.path:
            self.href = urlunparse(self.parts._replace(path=pathname))

    @property
    def search(self):
        return self.parts.query

    @search.setter
    def search(self, search):
        if search != self.parts.query:
            self.href = urlunparse(self.parts._replace(query=search))

    @property
    def hash(self):
        return self.parts.fragment

    @hash.setter
    def hash(self, fragment):
        if fragment != self.parts.fragment:
            self.href = urlunparse(self.parts._replace(fragment=fragment))

    def assign(self, url):
        self._window.open(url)

    def reload(self, force=False):
        self._window.open(self._window.url)

    def replace(self, url):
        self._window.open(url)
