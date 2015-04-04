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

import datetime
import logging

log = logging.getLogger("Thug")

MAX_COOKIE_EXPIRES_DAYS = 365 


class WebTracking(object):
    now = datetime.datetime.now()
    cookie_expires_delta = datetime.timedelta(days = MAX_COOKIE_EXPIRES_DAYS)

    def __init__(self):
        self.cookies = set()
    
    def _inspect_cookie_expires(self, cookie):
        expires = datetime.datetime.fromtimestamp(cookie.expires)
        if self.now + self.cookie_expires_delta < expires:
            log.ThugLogging.log_warning("[PRIVACY] Cookie expiring at %s (more than %s days from now)" % (expires,
                                                                                                          MAX_COOKIE_EXPIRES_DAYS, ))

    def _do_inspect_cookies(self, response):
        for cookie in response.cookies:
            self.cookies.add(cookie)
            self._inspect_cookie_expires(cookie)

    def _inspect_cookies(self, response):
        if response.history:
            for r in response.history:
                self._do_inspect_cookies(r)

        self._do_inspect_cookies(response)

    def inspect_response(self, response):
        if not log.ThugOpts.web_tracking:
            return

        self._inspect_cookies(response)
