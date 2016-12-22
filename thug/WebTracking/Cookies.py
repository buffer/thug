#!/usr/bin/env python
#
# Cookies.py
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


class Cookies(object):
    now = datetime.datetime.now()
    cookie_expires_delta = datetime.timedelta(days = MAX_COOKIE_EXPIRES_DAYS)

    def __init__(self):
        self.cookie_id = 1
        self.cookies = set()

    def _inspect_cookie_expires(self, cookie):
        if not cookie.expires:
            return

        expires = datetime.datetime.fromtimestamp(cookie.expires)
        if self.now + self.cookie_expires_delta < expires:
            log.ThugLogging.log_warning("[TRACKING] [Cookie #{}] Expiring at {} (more than {} days from now)".format(self.cookie_id,
                                                                                                                     expires,
                                                                                                                     MAX_COOKIE_EXPIRES_DAYS))

        if self.now > expires:
            log.ThugLogging.log_warning("[TRACKING] [Cookie #{}] Expired at {}".format(self.cookie_id, expires))

    def _inspect_cookie_domain_initial_dot(self, cookie):
        if cookie.domain_specified and cookie.domain_initial_dot:
            log.ThugLogging.log_warning("[TRACKING] [Cookie #{}] Domain starting with initial dot: {}".format(self.cookie_id,
                                                                                                              cookie.domain))

    def _inspect_cookie_path(self, cookie):
        if cookie.path_specified:
            log.ThugLogging.log_warning("[TRACKING] [Cookie #{}] Path: {}".format(self.cookie_id, cookie.path))

    def _inspect_cookie_port(self, cookie):
        if cookie.port_specified:
            log.ThugLogging.log_warning("[TRACKING] [Cookie #{}] Port: {}".format(self.cookie_id, cookie.port))

    def _inspect_cookie_secure(self, cookie):
        if cookie.secure:
            log.ThugLogging.log_warning("[TRACKING] [Cookie #{}] Secure flag set".format(self.cookie_id))

    def _do_inspect_cookies(self, response):
        for cookie in response.cookies:
            self.cookies.add(cookie)
            log.ThugLogging.log_warning("[TRACKING] [Cookie #{}] {}".format(self.cookie_id, cookie.value))

            self._inspect_cookie_expires(cookie)
            self._inspect_cookie_domain_initial_dot(cookie)
            self._inspect_cookie_path(cookie)
            self._inspect_cookie_port(cookie)
            self._inspect_cookie_secure(cookie)
            self.cookie_id += 1

    def inspect(self, response):
        if response.history:
            for r in response.history:
                self._do_inspect_cookies(r)

        self._do_inspect_cookies(response)
