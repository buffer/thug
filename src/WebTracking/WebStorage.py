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
 
class WebStorage(object):
    def __init__(self):
        self.storage = dict()

    def inspect_set_item(self, storage, key, value):
        log.ThugLogging.log_warning("[TRACKING] [%s setItem] %s = %s" % (storage, key, value, ))

    def inspect_remove_item(self, storage, key):
        log.ThugLogging.log_warning("[TRACKING] [%s removeItem] %s" % (storage, key, ))

    def inspect_clear(self, storage):
        log.ThugLogging.log_warning("[TRACKING] [%s clear]" % (storage, ))
