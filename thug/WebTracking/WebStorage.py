#!/usr/bin/env python
#
# WebStorage.py
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

log = logging.getLogger("Thug")


class WebStorage:
    def __init__(self):
        self.storage = dict()

    @staticmethod
    def inspect_set_item(storage, key, value):
        log.warning("[TRACKING] [%s setItem] %s = %s", storage, key, value)

    @staticmethod
    def inspect_remove_item(storage, key):
        log.warning("[TRACKING] [%s removeItem] %s", storage, key)

    @staticmethod
    def inspect_clear(storage):
        log.warning("[TRACKING] [%s clear]", storage)
