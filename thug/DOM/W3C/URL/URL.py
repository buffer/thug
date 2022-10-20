#!/usr/bin/env python
#
# URL.py
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

# URL Standard
# https://url.spec.whatwg.org/

import logging
import urllib.parse

from thug.DOM.JSClass import JSClass

from .URLSearchParams import URLSearchParams

log = logging.getLogger("Thug")


class URL(JSClass):
    protocols = ('http', 'https', 'ftp', )

    def __init__(self, url, base = None):
        self.init_url(url if base is None else urllib.parse.urljoin(base, url))

    def init_url(self, url):
        self.p_url = urllib.parse.urlparse(url)
        self.p_url = self.p_url._replace(path = urllib.parse.quote(self.p_url.path))

    def __get_port(self, port):
        if isinstance(port, str):
            if not port.isnumeric():
                return None

            port = int(port)

        return port if port in range(1, 65536) else None

    def get_hash(self):
        return f"#{self.p_url.fragment}"

    def set_hash(self, fragment):
        self.p_url = self.p_url._replace(fragment = fragment)

    hash = property(get_hash, set_hash)

    def get_host(self):
        return self.p_url.netloc

    def set_host(self, host):
        s_host = host.split(":")
        if len(s_host) > 1 and self.__get_port(s_host[1]) is None:
            return

        self.p_url = self.p_url._replace(netloc = host)

    host = property(get_host, set_host)

    def get_hostname(self):
        s_netloc = self.p_url.netloc.split(':')
        return s_netloc[0] if len(s_netloc) > 0 else ''

    def set_hostname(self, hostname):
        if ":" in hostname:
            return

        self.set_host(hostname)

    hostname = property(get_hostname, set_hostname)

    def get_href(self):
        return urllib.parse.urlunparse(self.p_url)

    def set_href(self, href):
        self.init_url(href)

    href = property(get_href, set_href)

    @property
    def origin(self):
        return f"{self.p_url.scheme}://{self.p_url.netloc}"

    def get_password(self):
        return self.p_url.password

    def set_password(self, password):
        s_netloc = self.p_url.netloc.split("@")

        if len(s_netloc) < 2:
            _netloc = f":{password}@{self.p_url.netloc}"
            self.p_url = self.p_url._replace(netloc = _netloc)
            return

        if not ":" in s_netloc[0]:
            s_netloc[0] = f"{s_netloc[0]}:{password}"
        else:
            s_netloc[0] = f"{s_netloc[0].split(':')[0]}:{password}"

        self.p_url = self.p_url._replace(netloc = "@".join(s_netloc))

    password = property(get_password, set_password)

    def get_pathname(self):
        return self.p_url.path

    def set_pathname(self, pathname):
        self.p_url = self.p_url._replace(path = pathname)

    pathname = property(get_pathname, set_pathname)

    def get_port(self):
        return self.p_url.port

    def set_port(self, port):
        _port = self.__get_port(port)
        if _port is None:
            return

        _netloc = self.p_url.netloc.split(":")[0]
        self.p_url = self.p_url._replace(netloc = f"{_netloc}:{_port}")

    port = property(get_port, set_port)

    def get_protocol(self):
        return f"{self.p_url.scheme}:"

    def set_protocol(self, protocol):
        if protocol in self.protocols:
            self.p_url = self.p_url._replace(scheme = protocol)

    protocol = property(get_protocol, set_protocol)

    def get_search(self):
        return self.p_url.query

    def set_search(self, search):
        self.p_url = self.p_url._replace(query = search)

    search = property(get_search, set_search)

    @property
    def searchParams(self):
        return URLSearchParams(self.p_url.query)

    def get_username(self):
        return self.p_url.username

    def set_username(self, username):
        s_netloc = self.p_url.netloc.split("@")

        if len(s_netloc) < 2:
            _netloc = f"{username}@{self.p_url.netloc}"
            self.p_url = self.p_url._replace(netloc = _netloc)
            return

        if not ":" in s_netloc[0]:
            s_netloc[0] = username
        else:
            s_netloc[0] = f"{username}:{s_netloc[0].split(':')[1]}"

        self.p_url = self.p_url._replace(netloc = "@".join(s_netloc))

    username = property(get_username, set_username)
