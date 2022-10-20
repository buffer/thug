#!/usr/bin/env python
#
# URLSearchParams.py
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

from thug.DOM.JSClass import JSClass

log = logging.getLogger("Thug")


class URLSearchParams(JSClass):
    def __init__(self, params = None):
        self.search_params = {}
        if params is None:
            return

        if not isinstance(params, str):
            for name in params.keys():
                if name not in self.search_params:
                    self.search_params[name] = []

                self.search_params[name].append(params[name])

            return

        if params.startswith("?"):
            params = params[1:]

        for item in params.split("&"):
            sitem = item.split("=")
            name  = sitem[0].strip()
            value = '' if len(sitem) < 2 else sitem[1].strip()

            if name not in self.search_params:
                self.search_params[name] = []

            self.search_params[name].append(value)

    def toString(self):
        items = []

        for key, values in self.search_params.items():
            items.append("&".join(f"{key}={value}" for value in values))

        return "&".join(items)

    def append(self, name, value):
        if name not in self.search_params:
            self.search_params[name] = []

        self.search_params[name].append(value)

    def delete(self, name):
        if name not in self.search_params:
            return

        del self.search_params[name]

    def get(self, name):
        if name not in self.search_params or len(self.search_params[name]) < 1:
            return None

        return self.search_params[name][0]

    def getAll(self, name):
        if name not in self.search_params or len(self.search_params[name]) < 1:
            return []

        return self.search_params[name]

    def has(self, name):
        return name in self.search_params

    def set(self, name, value):
        self.search_params[name] = [value, ]

    def sort(self):
        self.search_params = dict(sorted(self.search_params.items()))
