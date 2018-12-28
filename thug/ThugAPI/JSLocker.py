#!/usr/bin/env python
#
# JSLocker.py
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
import six.moves.configparser as ConfigParser

log = logging.getLogger("Thug")


class DummyJSLocker(object):
    def __init__(self, dummy = None):
        self.dummy = dummy

    def __enter__(self):
        return self.dummy

    def __exit__(self, *args):
        pass


class JSLocker(object):
    def __init__(self):
        self.init_jslocker()

    def init_v8_jslocker(self):
        import PyV8
        self._jslocker = PyV8.JSLocker

    def init_dummy_jslocker(self):
        self._jslocker = DummyJSLocker

    def init_jslocker(self):
        conf_file = os.path.join(log.configuration_path, 'thug.conf')
        config = ConfigParser.ConfigParser()
        config.read(conf_file)

        engine = config.get('jsengine', 'engine')
        jslocker_init = getattr(self, 'init_{}_jslocker'.format(engine), self.init_dummy_jslocker)
        jslocker_init()

    @property
    def jslocker(self):
        return self._jslocker
