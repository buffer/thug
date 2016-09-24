#!/usr/bin/env python
#
# BaseClassifier.py
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
import yara
import logging

log = logging.getLogger("Thug")

class BaseClassifier(object):
    def __init__(self):
        self._rules       = dict()
        self.matches      = list()
        self.namespace_id = 1
        self.init_rules()

    def init_rules(self):
        p = getattr(self, 'default_rule_file', None)
        if p is None:
            log.warn("[%s] Skipping not existing default classification rule file", self.classifier)
            return

        r = os.path.join(log.configuration_path, p)

        if not os.path.exists(r):
            log.warn("[%s] Skipping not existing default classification rule file", self.classifier)
            return

        self._rules['namespace0'] = r
        self.rules = yara.compile(filepaths = self._rules)

    def add_rule(self, rule_file):
        if not os.path.exists(rule_file):
            log.warn("[%s] Skipping not existing classification rule file %s", self.classifier, rule_file)
            return

        self._rules["namespace%s" % (self.namespace_id, )] = rule_file
        self.namespace_id += 1
        self.rules = yara.compile(filepaths = self._rules)

    @property
    def result(self):
        return self.matches
