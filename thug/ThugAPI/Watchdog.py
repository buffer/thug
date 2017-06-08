#!/usr/bin/env python
#
# Watchdog.py
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

import os
import signal
import logging

log = logging.getLogger("Thug")


class Watchdog(object):
    def __init__(self, time, callback = None):
        self.time     = time
        self.callback = callback

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handler)
        signal.alarm(self.time)

    def __exit__(self, exception_type, exception_value, traceback):
        signal.alarm(0)

    def handler(self, signum, frame):
        log.critical("The analysis took more than %d seconds. Aborting!", self.time)
        if self.callback:
            self.callback(signum, frame)

        log.ThugLogging.log_event()
        os.kill(os.getpid(), signal.SIGTERM)
