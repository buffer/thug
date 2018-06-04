#!/usr/bin/env python
#
# Debugger.py
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
import PyV8
import thug
import logging

log = logging.getLogger("Thug")


class Debugger(PyV8.JSDebugger):
    def __init__(self):
        PyV8.JSDebugger.__init__(self)
        # self.evalContext = PyV8.JSContext()

    def __enter__(self):
        script_filename = os.path.join(thug.__configuration_path__, 'scripts', 'd8.js')
        with self.context as ctxt:
            ctxt.eval(open(script_filename, 'r').read())

        PyV8.JSEngine.collect()
        # self.setEnabled(True)

        return PyV8.JSDebugger.__enter__(self)

    def onMessage(self, msg):
        log.debug("Debug message: %s", msg)

        if msg['type'] == 'event' and msg['event'] == 'break':
            self.stepNext()
        return True

    def onDebugEvent(self, _type, state, evt):
        json = evt.toJSONProtocol()
        log.debug("%s event: %s", _type, json)

    def onBreakEvent(self, evt):
        log.debug("Break event: %s", evt)

    def onException(self, evt):
        log.debug("Exception event: %s", evt)

    def onNewFunction(self, evt):
        log.debug("New function event: %s", evt)

    def onBeforeCompile(self, evt):
        log.debug("Before compile event: %s", evt)
        return True

    def onAfterCompile(self, evt):
        log.debug("After compile event: %s", evt)
        return True

    def processDebugEvent(self, evt):
        log.debug("Received debug event: %s", repr(evt))

    def onBreak(self):
        log.debug("onBreak")
