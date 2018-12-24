#!/usr/bin/env python
#
# Shellcode.py
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

import six
import logging
import pylibemu
import traceback

log = logging.getLogger("Thug")


class Shellcode(object):
    emu = pylibemu.Emulator(enable_hooks = False)

    def __init__(self, window, ctxt, ast, script):
        self.window  = window
        self.script  = script
        self.ctxt    = ctxt
        self.ast     = ast
        self.offsets = set()

    def check_URLDownloadToFile(self, emu):
        profile = emu.emu_profile_output

        while True:
            offset = profile.find('URLDownloadToFile')
            if offset < 0:
                break

            profile = profile[offset:]

            p = profile.split(';')
            if len(p) < 2:
                profile = profile[1:]
                continue

            p = p[1].split('"')
            if len(p) < 3:
                profile = profile[1:]
                continue

            url = p[1]
            if url in log.ThugLogging.shellcode_urls:
                return

            try:
                self.window._navigator.fetch(p[1], redirect_type = "Found URLDownloadToFile")
                log.ThugLogging.shellcode_urls.add(url)
            except Exception:
                pass

            profile = profile[1:]

    def search_url(self, sc):
        from thug.DOM.W3C import w3c
        from thug.DOM.Window import Window
        from thug.DOM.DFT import DFT

        offset = sc.find('http')

        if offset > 0:
            url = sc[offset:].split()[0]
            if url.endswith("'") or url.endswith('"'):
                url = url[:-1]

            if url in log.ThugLogging.shellcode_urls:
                return

            if url in log.ThugLogging.retrieved_urls:
                return

            log.info('[Shellcode Analysis] URL Detected: %s', url)

            try:
                response = self.window._navigator.fetch(url, redirect_type = "URL found")
                log.ThugLogging.shellcode_urls.add(url)
            except Exception:
                return

            if response is None:
                return

            if not response.ok:
                return

            doc    = w3c.parseString(response.content)
            window = Window(url, doc, personality = log.ThugOpts.useragent)

            dft = DFT(window)
            dft.run()

    @property
    def dump_url(self):
        if log.ThugOpts.local:
            return log.ThugLogging.url

        url = getattr(log, 'last_url_fetched', None)
        return url if url else self.window.url

    def dump_eval(self):
        name, saved = log.ThugLogging.eval_symbol

        # FIXME
        if not getattr(self.ctxt, "locals", None):
            return

        scripts = getattr(self.ctxt.locals, name, None)
        if scripts is None:
            return

        for script in scripts:
            if not isinstance(script, six.string_types):
                continue

            if log.ThugOpts.features_logging:
                log.ThugLogging.Features.increase_eval_count()

            try:
                log.warning("[eval] Deobfuscated argument: %s", script)
            except Exception:
                pass

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

        # FIXME
        if not getattr(self.ctxt, "locals", None):
            return

        htmls = getattr(self.ctxt.locals, name, None)
        if htmls is None:
            return

        for html in htmls:
            if not isinstance(html, six.string_types):
                continue

            try:
                log.warning("[document.write] Deobfuscated argument: %s", html)
            except Exception:
                pass

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
        with log.JSEngine.JSDebugger() as dbg:
            dbg._context = self.ctxt
            # dbg.debugBreak()

            try:
                result = self.ctxt.eval(self.script)
            except (UnicodeDecodeError, TypeError):
                try:
                    enc = log.Encoding.detect(self.script)
                    result = self.ctxt.eval(self.script.decode(enc['encoding']))
                except Exception:
                    self.dump()
                    log.ThugLogging.log_warning(traceback.format_exc())
                    return None
            except Exception:
                self.dump()
                log.ThugLogging.log_warning(traceback.format_exc())
                return None

            self.dump()

            names = [p['name'] for p in self.ast.names]
            for name in names:
                # FIXME
                if not getattr(self.ctxt, "locals", None):
                    continue

                s = getattr(self.ctxt.locals, name, None)

                if not s:
                    continue

                if not isinstance(s, six.string_types):
                    continue

                log.debug("[Shellcode] Testing variable: %s", name)
                self.emu.run(s)

                if self.emu.emu_profile_output:
                    try:
                        encoded_sc = s.encode('unicode-escape')
                    except Exception:
                        encoded_sc = "Unable to encode shellcode"

                    snippet = log.ThugLogging.add_shellcode_snippet(encoded_sc,
                                                                    "Assembly",
                                                                    "Shellcode")

                    log.ThugLogging.add_behavior_warn("[Shellcode Profile] {}".format(self.emu.emu_profile_output),
                                                      snippet = snippet,
                                                      method  = "Static Analysis")

                    self.check_URLDownloadToFile(self.emu)

                self.emu.free()
                self.search_url(s)

        return result
