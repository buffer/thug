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
from urllib.parse import urlparse
from urllib.parse import urlunparse

from thug.DOM.W3C import w3c

from .DFT import DFT
from .JSClass import JSClass

log = logging.getLogger("Thug")


class Location(JSClass):
    def __init__(self, window):
        self._window = window

    def toString(self): # pragma: no cover
        return self._window.url

    @property
    def parts(self):
        return urlparse(self._window.url)

    def get_href(self):
        return self._window.url

    def set_href(self, url):
        from .Window import Window

        if url.startswith("data:"): # pragma: no cover
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

        doc    = w3c.parseString('')
        window = Window(referer, doc, personality = p)  # pylint:disable=undefined-loop-variable
        window = window.open(url)
        if not window:
            return

        # self._window.url = url
        dft = DFT(window)
        dft.run()

    href = property(get_href, set_href)

    def get_protocol(self):
        return self.parts.scheme

    def set_protocol(self, protocol):
        if protocol in (self.parts.scheme, ):
            return

        self.set_href(urlunparse(self.parts._replace(scheme = protocol)))

    protocol = property(get_protocol, set_protocol)

    def get_host(self):
        return self.parts.netloc

    def set_host(self, host):
        if host in (self.parts.netloc, ):
            return

        self.set_href(urlunparse(self.parts._replace(netloc = host)))

    host = property(get_host, set_host)

    def get_hostname(self):
        return self.parts.hostname

    def set_hostname(self, hostname):
        snetloc = self.parts.netloc.split(':')

        if len(snetloc) and hostname in (snetloc[0], ):
            return

        host = "{}:{}".format(hostname, snetloc[1]) if len(snetloc) > 1 else hostname
        self.set_host(host)

    hostname = property(get_hostname, set_hostname)

    def get_port(self):
        return self.parts.port

    def set_port(self, port):
        snetloc = self.parts.netloc.split(':')

        if len(snetloc) > 1 and str(port) in (snetloc[1], ):
            return

        host = "{}:{}".format(snetloc[0], port)
        self.set_host(host)

    port = property(get_port, set_port)

    def get_pathname(self):
        return self.parts.path

    def set_pathname(self, pathname):
        if pathname in (self.parts.path, ):
            return

        self.set_href(urlunparse(self.parts._replace(path = pathname)))

    pathname = property(get_pathname, set_pathname)

    def get_search(self):
        return self.parts.query

    def set_search(self, search):
        if search in (self.parts.query, ):
            return

        self.set_href(urlunparse(self.parts._replace(query = search)))

    search = property(get_search, set_search)

    def get_hash(self):
        return self.parts.fragment

    def set_hash(self, fragment):
        if fragment in (self.parts.fragment, ):
            return

        self.set_href(urlunparse(self.parts._replace(fragment = fragment)))

    hash = property(get_hash, set_hash)

    def assign(self, url):
        """Loads a new HTML document."""
        self._window.open(url)

    def reload(self, force = False):
        """Reloads the current page."""
        self._window.open(self._window.url)

    def replace(self, url):
        """Replaces the current document by loading another document at the specified URL."""
        self._window.open(url)
