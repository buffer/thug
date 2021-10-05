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
    builtins = ('Map', 'Set', 'WeakMap', 'WeakSet', )

    def __init__(self):
        self.init_config()
        self.init_engine()

    @property
    def builtin_map(self):
        return [
            {
                'method'           : log.ThugOpts.Personality.isIE,
                'min_Map'          : 11,
                'min_Map_iter'     : 100,
                'min_Set'          : 11,
                'min_Set_iter'     : 100,
                'min_WeakMap'      : 11,
                'min_WeakMap_iter' : 100,
                'min_WeakSet'      : 100,
                'min_WeakSet_iter' : 100,
            },
            {
                'method'           : log.ThugOpts.Personality.isChrome,
                'min_Map'          : 38,
                'min_Map_iter'     : 38,
                'min_Set'          : 38,
                'min_Set_iter'     : 38,
                'min_WeakMap'      : 36,
                'min_WeakMap_iter' : 38,
                'min_WeakSet'      : 36,
                'min_WeakSet_iter' : 38,
            },
            {
                'method'           : log.ThugOpts.Personality.isFirefox,
                'min_Map'          : 13,
                'min_Map_iter'     : 13,
                'min_Set'          : 13,
                'min_Set_iter'     : 13,
                'min_WeakMap'      : 6,
                'min_WeakMap_iter' : 36,
                'min_WeakSet'      : 34,
                'min_WeakSet_iter' : 34,
            },
            {
                'method'           : log.ThugOpts.Personality.isSafari,
                'min_Map'          : 8,
                'min_Map_iter'     : 9,
                'min_Set'          : 8,
                'min_Set_iter'     : 9,
                'min_WeakMap'      : 8,
                'min_WeakMap_iter' : 9,
                'min_WeakSet'      : 9,
                'min_WeakSet_iter' : 9,
            },
        ]

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
        m = getattr(self, f"init_{self.engine}_context", None)
        if m:
            m(window) # pylint:disable=not-callable

    def init_scripts_thug(self, ctxt):
        thug_js = os.path.join(thug.__configuration_path__, 'scripts', "thug.js")
        with open(thug_js, encoding = 'utf-8', mode = 'r') as fd:
            thug_js_code = fd.read()

        ctxt.eval(thug_js_code)

    def init_scripts_storage(self, ctxt):
        if not log.ThugOpts.Personality.isIE():
            return

        if log.ThugOpts.Personality.browserMajorVersion < 8:
            storage_js = os.path.join(thug.__configuration_path__, 'scripts', "storage.js")
            with open(storage_js, encoding = 'utf-8', mode = 'r') as fd:
                storage_js_code = fd.read()

            ctxt.eval(storage_js_code)

    def init_scripts_date(self, ctxt):
        if not log.ThugOpts.Personality.isIE():
            return

        if log.ThugOpts.Personality.browserMajorVersion < 9:
            date_js = os.path.join(thug.__configuration_path__, 'scripts', "date.js")
            with open(date_js, encoding = 'utf-8', mode = 'r') as fd:
                date_js_code = fd.read()

            ctxt.eval(date_js_code)

    def undefine_object_iter(self, ctxt, jso):
        ctxt.eval(f"{jso}.prototype.forEach = undefined")

    def undefine_object(self, ctxt, jso):
        ctxt.eval(f"{jso} = undefined")

    def do_init_scripts_builtin(self, ctxt, item):
        for jso in self.builtins:
            if log.ThugOpts.Personality.browserMajorVersion < item[f"min_{jso}"]:
                self.undefine_object(ctxt, jso)
                continue

            if log.ThugOpts.Personality.browserMajorVersion < item[f"min_{jso}_iter"]:
                self.undefine_object_iter(ctxt, jso)

    def init_scripts_builtin(self, ctxt):
        for item in self.builtin_map:
            if item['method']():
                self.do_init_scripts_builtin(ctxt, item)
                return

    def init_hooks(self, ctxt):
        hooks_folder = os.path.join(thug.__configuration_path__, 'hooks')
        hooks = os.listdir(hooks_folder) if os.path.exists(hooks_folder) else []

        for hook in sorted([h for h in hooks if h.endswith('.js')]):
            with open(os.path.join(hooks_folder, hook), encoding = 'utf-8', mode = 'r') as fd: # pragma: no cover
                hook_code = fd.read()
                ctxt.eval(hook_code)

        for hook in ('eval', 'write'):
            js = os.path.join(thug.__configuration_path__, 'scripts', f'{hook}.js')
            if not os.path.exists(js): # pragma: no cover
                continue

            symbol = getattr(log.ThugLogging, f'{hook}_symbol')
            with open(js, encoding = 'utf-8', mode = 'r') as fd:
                js_code = fd.read()
                ctxt.eval(js_code % {'name': symbol[0], 'saved': symbol[1]})

    def init_scripts(self):
        with self._context as ctxt:
            self.init_scripts_thug(ctxt)
            self.init_scripts_storage(ctxt)
            self.init_scripts_date(ctxt)
            self.init_scripts_builtin(ctxt)

            self.init_hooks(ctxt)

    def init_v8_symbols(self):
        self.terminateAllThreads = V8.JSEngine.terminateAllThreads

    def init_symbols(self):
        m = getattr(self, f"init_{self.engine}_symbols", None)
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
        m = getattr(self, f"is_{self.engine}_jsfunction", None)
        return m(symbol) if m else False # pylint:disable=not-callable

    def is_v8_jsobject(self, symbol):
        return isinstance(symbol, V8.JSObject)

    def isJSObject(self, symbol):
        m = getattr(self, f"is_{self.engine}_jsobject", None)
        return m(symbol) if m else False # pylint:disable=not-callable
