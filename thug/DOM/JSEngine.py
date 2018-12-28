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

import sys
import os
import logging
import six.moves.configparser as ConfigParser

try:
    import PyV8
    V8_MODULE = True
except ImportError:
    V8_MODULE = False

try:
    import pyduktape2
    DUKTAPE_MODULE = True

    # FIXME
    class _DuktapeContext(pyduktape2.DuktapeContext):
        def __init__(self, *args, **kwargs):
            pyduktape2.DuktapeContext(self, *args, **kwargs)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def eval(self, js):
            return self.eval_js(js)
except ImportError:
    DUKTAPE_MODULE = False

import thug
from thug.Debugger.V8Debugger import V8Debugger
from thug.Debugger.DuktapeDebugger import DuktapeDebugger

log = logging.getLogger("Thug")



class JSEngine(object):
    def __init__(self, window = None):
        self.init_config()
        self.init_engine()
        self.init_context(window)
        self.init_scripts()
        self.init_symbols()

    def init_config(self):
        conf_file = os.path.join(log.configuration_path, 'thug.conf')
        self.config = ConfigParser.ConfigParser()
        self.config.read(conf_file)

    def init_engine(self):
        self.engine = self.config.get('jsengine', 'engine')

    def init_v8_context(self, window):
        if not V8_MODULE:
            log.critical("PyV8 not installed. Please review Thug dependencies and configuration")
            sys.exit(1)

        self._context = PyV8.JSContext(window, extensions = log.JSExtensions)
        PyV8.JSEngine.setStackLimit(10 * 1024 * 1024)

    def init_duktape_context(self, window):
        if not DUKTAPE_MODULE:
            log.critical("Duktape not installed. Please review Thug dependencies and configuration")
            sys.exit(1)

        self._context = _DuktapeContext()
        # FIXME
        self._context.set_globals(this = window)

    def init_context(self, window):
        m = getattr(self, "init_{}_context".format(self.engine), None)
        if m:
            m(window)

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
            ctxt.eval(open(os.path.join(hooks_folder, hook), 'r').read())

        for hook in ('eval', 'write'):
            js = os.path.join(thug.__configuration_path__, 'scripts', '{}.js'.format(hook))
            if not os.path.exists(js):
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
            self.post_init_scripts()

    def post_init_scripts(self):
        if self.engine in ("v8", ):
            PyV8.JSEngine.collect()

    def init_v8_symbols(self):
        self.JSDebugger = V8Debugger
        self.collect = PyV8.JSEngine.collect
        self.terminateAllThreads = PyV8.JSEngine.terminateAllThreads
        self.setStackLimit = PyV8.JSEngine.setStackLimit

    def passthrough(self, *args, **kwargs):
        pass

    def init_duktape_symbols(self):
        self.JSDebugger = DuktapeDebugger
        self.collect = self.passthrough
        self.terminateAllThreads = self.passthrough
        self.setStackLimit = self.passthrough

    def init_symbols(self):
        m = getattr(self, "init_{}_symbols".format(self.engine), None)
        if m:
            m()

    @property
    def context(self):
        return self._context

    def is_v8_jsfunction(self, symbol):
        return isinstance(symbol, PyV8.JSFunction)

    def is_duktape_jsfunction(self, symbol):
        return self._context.eval(symbol) in ('function', )

    def isJSFunction(self, symbol):
        m = getattr(self, "is_{}_jsfunction".format(self.engine), None)
        if m:
            return m(symbol)

        return False

    def is_v8_jsobject(self, symbol):
        return isinstance(symbol, PyV8.JSObject)

    def is_duktape_jsobject(self, symbol):
        return self._context.eval(symbol) in ('object', )

    def isJSObject(self, symbol):
        m = getattr(self, "is_{}_jsfunction".format(self.engine), None)
        if m:
            return m(symbol)

        return False
