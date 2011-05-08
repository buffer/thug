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
import threading
import logging
import PyV8

class Debugger(PyV8.JSDebugger, threading.Thread):
    log = logging.getLogger("dbg")

    def __init__(self, debug = False):
        PyV8.JSDebugger.__init__(self)
        threading.Thread.__init__(self, name='dbg')
        
        self.terminated  = False
        self.exitcode    = None
        self.daemon      = True
        self.evalContext = PyV8.JSContext()

        if debug:
            self.log.setLevel(logging.DEBUG)

    def __enter__(self):
        script_filename = os.path.join(os.path.dirname(__file__), 'd8.js')

        self.log.debug("loading d8.js from %s", script_filename)

        with self.context as ctxt:
            ctxt.eval(open(script_filename, 'r').read())

        return PyV8.JSDebugger.__enter__(self)

    def onMessage(self, msg):
        self.log.debug("Debug message: %s" % (msg, ))
        
        if msg['type'] == 'event' and msg['event'] == 'break':
            self.stepNext()
        
        return True

    def onDebugEvent(self, type, state, evt):
        json = evt.toJSONProtocol()
        self.log.debug("%s event: %s" % (type, json, ))

    def onBreak(self, evt):
        self.log.debug("Break event: %s" % (evt, ))

    def onException(self, evt):
        self.log.debug("Exception event: %s" % (evt, ))

    def onNewFunction(self, evt):
        self.log.debug("New function event: %s" % (evt, ))

    def onBeforeCompile(self, evt):
        self.log.debug("Before compile event: %s" % (evt, ))

    def onAfterCompile(self, evt):
        self.log.debug("After compile event: %s" % (evt, ))

