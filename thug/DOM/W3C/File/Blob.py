#!/usr/bin/env python
#
# Blob.py
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

# File API
# https://w3c.github.io/FileAPI/

from promise import Promise
import STPyV8

from thug.DOM.JSClass import JSClass
from thug.DOM.W3C.Core.DOMException import DOMException


class Blob(JSClass):
    def __init__(self, array = None, options = None):
        self.array = STPyV8.JSArray() if array is None else array

        if options is None:
            options = {}

        try:
            self.options = dict(options)
        except ValueError:
            raise DOMException(DOMException.NOT_SUPPORTED_ERR) # pylint: disable=raise-missing-from

    @staticmethod
    def __convert(obj):
        if isinstance(obj, STPyV8.JSArray):
            return [Blob.__convert(v) for v in obj]

        if isinstance(obj, STPyV8.JSObject):
            return [Blob.__convert(obj.__getattr__(str(k))) for k in obj.__dir__()]

        if isinstance(obj, Blob):
            return [Blob.__convert(v) for v in obj.array]

        return obj

    @property
    def blob(self):
        return [j for i in self.__convert(self.array) for j in i]

    @property
    def size(self):
        return len(self.blob)

    @property
    def type(self):
        return self.options.get("type", "").lower()

    @property
    def endings(self):
        return self.options.get("endings", "transparent").lower()

    def text(self):
        return Promise(
            lambda resolve, reject: resolve(''.join(self.blob))
        )

    def arrayBuffer(self):
        return Promise(
            lambda resolve, reject: resolve(self.array)
        )

    def slice(self, start = 0, end = None, contentType = ""):
        options = {}
        options["type"] = contentType

        end = self.size if end is None else end
        return Blob(self.blob[start:end], options)
