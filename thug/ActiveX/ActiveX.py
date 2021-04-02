#!/usr/bin/env python
#
# ActiveX.py
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

# import new
import logging
from .CLSID import CLSID

log = logging.getLogger("Thug")

acropdf   = ( 'acropdf.pdf',
              'pdf.pdfctrl',
              'CA8A9780-280D-11CF-A24D-444553540000', )


shockwave = ( 'shockwaveflash.shockwaveflash',
              'shockwaveflash.shockwaveflash.1',
              'shockwaveflash.shockwaveflash.9',
              'shockwaveflash.shockwaveflash.10',
              'shockwaveflash.shockwaveflash.11',
              'shockwaveflash.shockwaveflash.12',
              'swctl.swctl',
              'swctl.swctl.8',
              '233C1507-6A77-46A4-9443-F871F945D258', )


silverlight = ( 'agcontrol.agcontrol', )

java_deployment_toolkit = ( 'CAFEEFAC-DEC7-0000-0000-ABCDEFFEDCBA',
                            '8AD9C840-044E-11D1-B3E9-00805F499D93', )


class _ActiveXObject:
    def __init__(self, window, cls, typename = 'name'):
        self.funcattrs = dict()
        self._window   = window
        obj            = None
        methods        = dict()
        self.cls       = cls

        self.shockwave = log.ThugVulnModules.shockwave_flash.split('.')[0]
        self.shockwave_flash = { 'shockwaveflash.shockwaveflash'    : self.shockwave,
                                 'shockwaveflash.shockwaveflash.1'  : self.shockwave,
                                 'shockwaveflash.shockwaveflash.9'  : '9' ,
                                 'shockwaveflash.shockwaveflash.10' : '10',
                                 'shockwaveflash.shockwaveflash.11' : '11',
                                 'shockwaveflash.shockwaveflash.12' : '12' }

        if typename == 'id':
            if len(cls) > 5 and cls[:6].lower() == 'clsid:':
                cls = cls[6:].upper()

            if cls.startswith('{') and cls.endswith('}'):
                cls = cls[1:-1]

        if typename == 'name':
            cls = cls.lower()

        # Adobe Acrobat Reader
        if cls in acropdf and log.ThugVulnModules.acropdf_disabled:
            log.warning("Unknown ActiveX Object: %s", cls)
            raise TypeError()

        # Shockwave Flash
        if cls in shockwave and log.ThugVulnModules.shockwave_flash_disabled:
            log.warning("Unknown ActiveX Object: %s", cls)
            raise TypeError()

        if cls in self.shockwave_flash:
            if cls in ('shockwaveflash.shockwaveflash', 'shockwaveflash.shockwaveflash.1'):
                version = self.shockwave_flash[cls]
                cls = 'shockwaveflash.shockwaveflash.{}'.format(version)

            if self.shockwave not in (self.shockwave_flash[cls], ):
                log.warning("Unknown ActiveX Object: %s", cls)
                raise TypeError()

        _cls = cls

        # Java Deployment Toolkit
        if cls in java_deployment_toolkit and log.ThugVulnModules.javaplugin_disabled:
            log.warning("Unknown ActiveX Object: %s", cls)
            raise TypeError()

        # JavaPlugin
        if cls.lower().startswith('javaplugin'):
            if log.ThugVulnModules.javaplugin_disabled or not cls.endswith(log.ThugVulnModules.javaplugin):
                log.warning("Unknown ActiveX Object: %s", cls)
                raise TypeError()

            _cls = 'javaplugin'

        # JavaWebStart
        if cls.lower().startswith('javawebstart.isinstalled'):
            if log.ThugVulnModules.javaplugin_disabled or not cls.endswith(log.ThugVulnModules.javawebstart_isinstalled):
                log.warning("Unknown ActiveX Object: %s", cls)
                raise TypeError()

            _cls = 'javawebstart.isinstalled'

        if cls in silverlight and log.ThugVulnModules.silverlight_disabled:
            log.warning("Unknown ActiveX Object: %s", cls)
            raise TypeError()

        for c in CLSID:
            if _cls in c[typename]:
                obj = c
                break

        if not obj:
            log.warning("Unknown ActiveX Object: %s", cls)
            raise TypeError()

        if log.ThugOpts.activex_ready:
            log.warning("ActiveXObject: %s", cls)

        if log.ThugOpts.features_logging and log.ThugOpts.activex_ready:
            log.ThugLogging.Features.increase_activex_count()

        for method_name, method in obj['methods'].items():
            # _method = new.instancemethod(method, self, _ActiveXObject)
            _method = method.__get__(self, _ActiveXObject)
            setattr(self, method_name, _method)
            methods[method] = _method

        for attr_name, attr_value in obj['attrs'].items():
            setattr(self, attr_name, attr_value)

        for attr_name, attr_value in obj['funcattrs'].items():
            self.funcattrs[attr_name] = methods[attr_value]

        if cls.lower() in ('wscript.shell', ):
            self.scriptFullName = log.ThugLogging.url if log.ThugOpts.local else ''

    def __setattr__(self, name, value):
        self.__dict__[name] = value

        if name in self.funcattrs:
            self.funcattrs[name](value)

    def __getattr__(self, name):
        for key, value in self.__dict__.items():
            if key.lower() == name.lower():
                return value

        if name in self.funcattrs:
            value = self.funcattrs[name]()
            self.__dict__[name] = value
            return value

        if name not in ('__watchpoints__', ):
            log.warning("Unknown ActiveX Object (%s) attribute: %s", self.cls, name)

        raise AttributeError


def register_object(s, clsid):
    funcattrs = dict()  # pylint:disable=unused-variable
    methods   = dict()
    obj       = None

    if not clsid.startswith('clsid:'):
        log.warning("Unknown ActiveX object: %s", clsid)
        return

    clsid = clsid[6:].upper()
    if clsid.startswith('{') and clsid.endswith('}'):
        clsid = clsid[1:-1]

    # Adobe Acrobat Reader
    if clsid in acropdf and log.ThugVulnModules.acropdf_disabled:
        log.warning("Unknown ActiveX Object: %s", clsid)
        raise TypeError()

    # Shockwave Flash
    if clsid in shockwave and log.ThugVulnModules.shockwave_flash_disabled:
        log.warning("Unknown ActiveX Object: %s", clsid)
        raise TypeError()

    # Java Deployment Toolkit
    if clsid in java_deployment_toolkit and log.ThugVulnModules.javaplugin_disabled:
        log.warning("Unknown ActiveX Object: %s", clsid)
        raise TypeError()

    for c in CLSID:
        if clsid in c['id']:
            obj = c
            break

    if obj is None:
        log.warning("Unknown ActiveX object: %s", clsid)
        raise TypeError()

    log.warning("ActiveXObject: %s", clsid)

    for method_name, method in obj['methods'].items():
        # _method = new.instancemethod(method, s, s.__class__)
        _method = method.__get__(s, s.__class__)
        setattr(s, method_name, _method)
        methods[method] = _method

    for attr_name, attr_value in obj['attrs'].items():
        setattr(s, attr_name, attr_value)

    # PLEASE REVIEW ME!
    for attr_name, attr_value in obj['funcattrs'].items():
        if 'funcattrs' not in s.__dict__:
            s.__dict__['funcattrs'] = dict()

        s.__dict__['funcattrs'][attr_name] = methods[attr_value]
