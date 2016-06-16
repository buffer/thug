#!/usr/bin/env python
#
# ThugVulnModules.py
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

class ThugVulnModules(dict):
    def __init__(self):
        self._acropdf_pdf               = '9.1.0'
        self._acropdf_disabled          = False
        self._shockwave_flash           = '10.0.64.0'
        self._shockwave_flash_disabled  = False
        self._javaplugin                = '1.6.0.32'
        self._javaplugin_disabled       = False

    def invalid_version(self, version):
        for p in version.split('.'):
            if not p.isdigit():
                return True

        return False

    def get_acropdf_pdf(self):
        return self._acropdf_pdf

    @property
    def acropdf(self):
        return self._acropdf_pdf

    def set_acropdf_pdf(self, version):
        if self.invalid_version(version):
            log.warning('[WARNING] Invalid Adobe Acrobat Reader version provided (using default one)')
            return

        self._acropdf_pdf = version

    acropdf_pdf = property(get_acropdf_pdf, set_acropdf_pdf)

    def disable_acropdf(self):
        self._acropdf_disabled = True

    @property
    def acropdf_disabled(self):
        return self._acropdf_disabled

    def get_shockwave_flash(self):
        return self._shockwave_flash

    def set_shockwave_flash(self, version):
        if not version.split('.')[0] in ('8', '9', '10', '11', '12', ) or self.invalid_version(version):
            log.warning('[WARNING] Invalid Shockwave Flash version provided (using default one)')
            return

        self._shockwave_flash = version

    shockwave_flash = property(get_shockwave_flash, set_shockwave_flash)

    def disable_shockwave_flash(self):
        self._shockwave_flash_disabled = True

    @property
    def shockwave_flash_disabled(self):
        return self._shockwave_flash_disabled

    def get_javaplugin(self):
        javaplugin = self._javaplugin.split('.')
        last       = javaplugin.pop()
        return '%s_%s' % (''.join(javaplugin), last)

    def set_javaplugin(self, version):
        if self.invalid_version(version):
            log.warning('[WARNING] Invalid JavaPlugin version provided (using default one)')
            return

        _version = version.split('.')
        while len(_version) < 4:
            _version.append('0')

        if len(_version[3]) == 1:
            _version[3] = '0%s' % (_version[3], )

        self._javaplugin = '.'.join(_version)

    javaplugin = property(get_javaplugin, set_javaplugin)

    def disable_javaplugin(self):
        self._javaplugin_disabled = True

    @property
    def javaplugin_disabled(self):
        return self._javaplugin_disabled

    @property
    def javawebstart_isinstalled(self):
        javawebstart = self._javaplugin.split('.')
        last         = javawebstart.pop() #pylint:disable=unused-variable
        return '%s.%s' % ('.'.join(javawebstart), '0')
