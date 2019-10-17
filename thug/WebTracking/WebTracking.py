#!/usr/bin/env python
#
# WebTracking.py
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

from .Cookies import Cookies
from .WebStorage import WebStorage

log = logging.getLogger("Thug")


class WebTracking(object):
    def __init__(self):
        self.cookies    = Cookies()
        self.webstorage = WebStorage()

    def inspect_response(self, response):
        if not log.ThugOpts.web_tracking: # pragma: no cover
            return

        self.cookies.inspect(response)

    def inspect_storage_setitem(self, storage, key, value):
        if not log.ThugOpts.web_tracking:
            return

        self.webstorage.inspect_set_item(storage, key, value)

    def inspect_storage_removeitem(self, storage, key):
        if not log.ThugOpts.web_tracking:
            return

        self.webstorage.inspect_remove_item(storage, key)

    def inspect_storage_clear(self, storage):
        if not log.ThugOpts.web_tracking:
            return

        self.webstorage.inspect_clear(storage)
