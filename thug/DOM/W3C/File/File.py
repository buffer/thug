#!/usr/bin/env python
#
# File.py
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

import logging

from .Blob import Blob

log = logging.getLogger("Thug")


class File(Blob):
    def __init__(self, bits, name, options = None):
        self.name = name
        Blob.__init__(self, bits, options)

        self.__handle()

    def __handle_zip(self):
        content = bytearray()
        for item in self.blob:
            content.extend(item)

        log.ThugLogging.log_file(bytes(content), self.name, sampletype = 'ZIP')

    def __handle(self):
        _type = self.options.get("type", None)
        if _type is None:
            return # pragma: no cover

        if _type.lower() in ('application/zip', ):
            self.__handle_zip()
