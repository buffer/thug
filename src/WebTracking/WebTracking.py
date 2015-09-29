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

from .Cookies import Cookies

import logging
log = logging.getLogger("Thug")


class WebTracking(object):
    def __init__(self):
        self.cookies = Cookies()

    def inspect_response(self, response):
        if not log.ThugOpts.web_tracking:
            return

        self.cookies.inspect(response)
