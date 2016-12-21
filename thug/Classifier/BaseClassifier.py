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
        self.matches = list()
        self.init_rules()
        self.init_filters()

    def init_rules(self):
        self._rules = dict()
        self.rules_namespace_id = 1

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

    def init_filters(self):
        self._filters = dict()
        self.filters_namespace_id = 1

        p = getattr(self, 'default_filter_file', None)
        if p is None:
            log.warn("[%s] Skipping not existing default filter file", self.classifier)
            return

        r = os.path.join(log.configuration_path, p)

        if not os.path.exists(r):
            log.warn("[%s] Skipping not existing default filter file", self.classifier)
            return

        self._filters['namespace0'] = r
        self.filters = yara.compile(filepaths = self._filters)

    def add_rule(self, rule_file):
        if not os.path.exists(rule_file):
            log.warn("[%s] Skipping not existing classification rule file %s", self.classifier, rule_file)
            return

        self._rules["namespace{}".format(self.rules_namespace_id)] = rule_file
        self.rules_namespace_id += 1
        self.rules = yara.compile(filepaths = self._rules)

    def add_filter(self, filter_file):
        if not os.path.exists(filter_file):
            log.warn("[%s] Skipping not existing filter file %s", self.classifier, filter_file)
            return

        self._filters["namespace{}".format(self.filters_namespace_id)] = filter_file
        self.filters_namespace_id += 1
        self.filters = yara.compile(filepaths = self._filters)

    @property
    def result(self):
        return self.matches
