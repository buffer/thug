#!/usr/bin/env python
#
# JSInspector.py
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


class JSInspector:
    def __init__(self, window, ctxt, script):
        self.window  = window
        self.script  = script
        self.ctxt    = ctxt

    @property
    def dump_url(self):
        if log.ThugOpts.local:
            return log.ThugLogging.url

        url = getattr(log, 'last_url', None)
        return url if url else self.window.url

    def dump_eval(self):
        name, saved = log.ThugLogging.eval_symbol

        if not getattr(self.ctxt, "locals", None): # pragma: no cover
            return

        scripts = getattr(self.ctxt.locals, name, None)
        if scripts is None:
            return

        for script in scripts:
            if not isinstance(script, str):
                continue

            if log.ThugOpts.features_logging:
                log.ThugLogging.Features.increase_eval_count()

            try:
                log.ThugLogging.add_behavior_warn("[eval] Deobfuscated argument: {}".format(script))
            except Exception as e: # pragma: no cover
                log.warning("[JSInspector] dump_eval warning: %s", str(e))

            log.JSClassifier.classify(self.dump_url, script)
            log.ThugLogging.add_code_snippet(script,
                                             language = 'Javascript',
                                             relationship = 'eval argument',
                                             check = True,
                                             force = True)

        delattr(self.ctxt.locals, name)
        delattr(self.ctxt.locals, saved)

    def dump_write(self):
        name, saved = log.ThugLogging.write_symbol

        if not getattr(self.ctxt, "locals", None): # pragma: no cover
            return

        htmls = getattr(self.ctxt.locals, name, None)
        if htmls is None:
            return

        for html in htmls:
            if not isinstance(html, str):
                continue

            try:
                log.ThugLogging.add_behavior_warn("[document.write] Deobfuscated argument: {}".format(html))
            except Exception as e: # pragma: no cover
                log.warning("[JSInspector] dump_write warning: %s", str(e))

            log.HTMLClassifier.classify(self.dump_url, html)
            log.ThugLogging.add_code_snippet(html,
                                             language = 'HTML',
                                             relationship = 'document.write argument',
                                             check = True,
                                             force = True)

        delattr(self.ctxt.locals, name)
        delattr(self.ctxt.locals, saved)

    def dump(self):
        self.dump_eval()
        self.dump_write()

    def run(self):
        result = None

        try:
            result = self.ctxt.eval(self.script)
        except (UnicodeDecodeError, TypeError) as e:
            if '\\u' in self.script:
                try:
                    result = self.ctxt.eval(self.script.replace('\\u', '%u'))
                except Exception as e: # pragma: no cover
                    log.warning("[JSInspector] %s", str(e))
        except Exception as e:
            log.warning("[JSInspector] %s", str(e))

        self.dump()
        return result
