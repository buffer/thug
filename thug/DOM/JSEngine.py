#!/usr/bin/env python
#
# JSEngine.py
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
import logging
import configparser

try:
    import STPyV8 as V8
except ImportError: # pragma: no cover
    import PyV8 as V8

import thug

log = logging.getLogger("Thug")


class JSEngine:
    def __init__(self):
        self.init_config()
        self.init_engine()

    def init_config(self):
        conf_file = os.path.join(log.configuration_path, 'thug.conf')
        self.config = configparser.ConfigParser()
        self.config.read(conf_file)

    def init_engine(self):
        self.engine = self.config.get('jsengine', 'engine')

    @property
    def JSLocker(self):
        return V8.JSLocker()

    def init_v8_context(self, window):
        self._context = V8.JSContext(window)
        V8.JSEngine.setStackLimit(1024 * 1024)

    def do_init_context(self, window):
        m = getattr(self, "init_{}_context".format(self.engine), None)
        if m:
            m(window) # pylint:disable=not-callable

    def init_scripts_thug(self, ctxt):
        thug_js = os.path.join(thug.__configuration_path__, 'scripts', "thug.js")
        ctxt.eval(open(thug_js, 'r').read())

    def init_scripts_storage(self, ctxt):
        if log.ThugOpts.Personality.browserMajorVersion < 8:
            storage_js = os.path.join(thug.__configuration_path__, 'scripts', "storage.js")
            ctxt.eval(open(storage_js, 'r').read())

    def init_scripts_date(self, ctxt):
        if log.ThugOpts.Personality.browserMajorVersion < 9:
            date_js = os.path.join(thug.__configuration_path__, 'scripts', "date.js")
            ctxt.eval(open(date_js, 'r').read())

    def init_hooks(self, ctxt):
        hooks_folder = os.path.join(thug.__configuration_path__, 'hooks')
        hooks = os.listdir(hooks_folder) if os.path.exists(hooks_folder) else list()

        for hook in sorted([h for h in hooks if h.endswith('.js')]):
            ctxt.eval(open(os.path.join(hooks_folder, hook), 'r').read()) # pragma: no cover

        for hook in ('eval', 'write'):
            js = os.path.join(thug.__configuration_path__, 'scripts', '{}.js'.format(hook))
            if not os.path.exists(js): # pragma: no cover
                continue

            symbol = getattr(log.ThugLogging, '{}_symbol'.format(hook))
            ctxt.eval(open(js, 'r').read() % {'name': symbol[0], 'saved': symbol[1]})

    def init_scripts(self):
        with self._context as ctxt:
            self.init_scripts_thug(ctxt)

            if log.ThugOpts.Personality.isIE():
                self.init_scripts_storage(ctxt)
                self.init_scripts_date(ctxt)

            self.init_hooks(ctxt)

    def init_v8_symbols(self):
        self.terminateAllThreads = V8.JSEngine.terminateAllThreads

    def init_symbols(self):
        m = getattr(self, "init_{}_symbols".format(self.engine), None)
        if m:
            m() # pylint:disable=not-callable

    @property
    def context(self):
        return self._context

    def init_context(self, window):
        self.do_init_context(window)
        self.init_scripts()
        self.init_symbols()

    def is_v8_jsfunction(self, symbol):
        return isinstance(symbol, V8.JSFunction)

    def isJSFunction(self, symbol):
        m = getattr(self, "is_{}_jsfunction".format(self.engine), None)
        return m(symbol) if m else False # pylint:disable=not-callable

    def is_v8_jsobject(self, symbol):
        return isinstance(symbol, V8.JSObject)

    def isJSObject(self, symbol):
        m = getattr(self, "is_{}_jsobject".format(self.engine), None)
        return m(symbol) if m else False # pylint:disable=not-callable
