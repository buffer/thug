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


import pprint
import logging

try:
    import pylibemu
    PYLIBEMU_MODULE = True
except ImportError: # pragma: no cover
    PYLIBEMU_MODULE = False

try:
    import speakeasy
    SPEAKEASY_MODULE = True
except ImportError: # pragma: no cover
    SPEAKEASY_MODULE = False


log = logging.getLogger("Thug")


class Shellcode(object):
    modules = ('pylibemu', 'speakeasy', )

    def __init__(self):
        self.enabled = any([PYLIBEMU_MODULE, SPEAKEASY_MODULE, ])

    @property
    def window(self):
        return log.DFT.window

    def check_URLDownloadToFile(self, emu, snippet):
        profile = emu.emu_profile_output.decode()

        while True:
            offset = profile.find('URLDownloadToFile')
            if offset < 0:
                break

            profile = profile[offset:]

            p = profile.split(';')
            if len(p) < 2: # pragma: no cover
                profile = profile[1:]
                continue

            p = p[1].split('"')
            if len(p) < 3:
                profile = profile[1:]
                continue

            url = p[1]
            if url in log.ThugLogging.shellcode_urls: # pragma: no cover
                return

            try:
                if self.window._navigator.fetch(url, redirect_type = "URLDownloadToFile", snippet = snippet) is None:
                    log.ThugLogging.add_behavior_warn('[URLDownloadToFile] Fetch failed', snippet = snippet)

                log.ThugLogging.shellcode_urls.add(url)
            except Exception:
                log.ThugLogging.add_behavior_warn('[URLDownloadToFile] Fetch failed', snippet = snippet)

            profile = profile[1:]

    def check_WinExec(self, emu, snippet):
        profile = emu.emu_profile_output.decode()

        while True:
            offset = profile.find('WinExec')
            if offset < 0:
                break

            profile = profile[offset:]

            p = profile.split(';')
            if not p: # pragma: no cover
                profile = profile[1:]
                continue

            s = p[0].split('"')
            if len(s) < 2: # pragma: no cover
                profile = profile[1:]
                continue

            url = s[1]
            if not url.startswith("\\\\"):
                profile = profile[1:]
                continue

            if url in log.ThugLogging.shellcode_urls: # pragma: no cover
                return

            log.ThugLogging.shellcode_urls.add(url)

            try:
                url = url[2:].replace("\\", "/")
                self.window._navigator.fetch(url, redirect_type = "WinExec", snippet = snippet)
            except Exception:
                log.ThugLogging.add_behavior_warn('[WinExec] Fetch failed', snippet = snippet)

            profile = profile[1:]

    def build_shellcode(self, s):
        i  = 0
        sc = list()

        while i < len(s):
            if s[i] == '"': # pragma: no cover
                i += 1
                continue

            if s[i] in ('%', ) and (i + 1) < len(s) and s[i + 1] == 'u':
                if (i + 6) <= len(s):
                    currchar = int(s[i + 2: i + 4], 16)
                    nextchar = int(s[i + 4: i + 6], 16)
                    sc.append(nextchar)
                    sc.append(currchar)
                    i += 6
                elif (i + 3) <= len(s): # pragma: no cover
                    currchar = int(s[i + 2: i + 4], 16)
                    sc.append(currchar)
                    i += 3
            else:
                sc.append(ord(s[i]))
                i += 1

        return bytes(sc)

    @staticmethod
    def build_snippet(shellcode):
        return log.ThugLogging.add_shellcode_snippet(shellcode,
                                                     "Assembly",
                                                     "Shellcode",
                                                     method = "Static Analysis")

    @staticmethod
    def log_shellcode_profile(module, profile, snippet):
        description = "[{}][Shellcode Profile] {}".format(module, profile)

        log.ThugLogging.add_behavior_warn(description = description,
                                          snippet     = snippet,
                                          method      = "Static Analysis")

    def check_shellcode_pylibemu(self, shellcode, sc, snippet):
        if not PYLIBEMU_MODULE: # pragma: no cover
            return snippet

        emu = pylibemu.Emulator(enable_hooks = False)
        emu.run(sc)

        if emu.emu_profile_output:
            profile = emu.emu_profile_output.decode()

            if snippet is None:
                snippet = self.build_snippet(shellcode)

            self.log_shellcode_profile("LIBEMU", profile, snippet)

            self.check_URLDownloadToFile(emu, snippet)
            self.check_WinExec(emu, snippet)

        emu.free()

        return snippet

    def check_shellcode_speakeasy(self, shellcode, sc, snippet):
        if not SPEAKEASY_MODULE:
            return snippet # pragma: no cover

        se = speakeasy.Speakeasy()

        address = se.load_shellcode(None, speakeasy.arch.ARCH_X86, data = sc)
        se.run_shellcode(address)

        if snippet is None:
            snippet = self.build_snippet(shellcode)

        self.log_shellcode_profile("SPEAKEASY", se.get_report(), snippet)
        return snippet

    def do_check_shellcode(self, shellcode, sc):
        snippet = None

        for module in self.modules:
            m = getattr(self, "check_shellcode_{}".format(module), None)
            if m is None:
                continue # pragma: no cover

            s = m(shellcode, sc, snippet)
            snippet = s if snippet is None else snippet

    def check_shellcode(self, shellcode):
        if not self.enabled: # pragma: no cover
            return

        if not shellcode:
            return

        try:
            sc = self.build_shellcode(shellcode)
        except Exception as e: # pragma: no cover
            log.info("Shellcode building error (%s)", str(e))
            return

        self.do_check_shellcode(shellcode, sc)

    def check_shellcodes(self):
        while True:
            try:
                shellcode = log.ThugLogging.shellcodes.pop()
                self.check_shellcode(shellcode)
            except KeyError:
                break
