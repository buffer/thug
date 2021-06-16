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
import operator
import logging

from urllib.parse import urlparse

import yara

log = logging.getLogger("Thug")


class BaseClassifier:
    def __init__(self):
        self.matches = list()
        self.custom_classifiers = dict()
        self.init_rules()
        self.init_filters()

    @property
    def classifier(self):
        return getattr(self, '_classifier', '')

    def init_rules(self):
        self._rules = dict()
        self.rules_namespace_id = 1

        p = getattr(self, 'default_rule_file', None)
        if p is None: # pragma: no cover
            log.warning("[%s] Skipping not existing default classification rule file", self.classifier)
            return

        r = os.path.join(log.configuration_path, p)

        if not os.path.exists(r): # pragma: no cover
            log.warning("[%s] Skipping not existing default classification rule file", self.classifier)
            return

        self._rules['namespace0'] = r
        self.rules = yara.compile(filepaths = self._rules)

    def init_filters(self):
        self._filters = dict()
        self.filters_namespace_id = 1

        p = getattr(self, 'default_filter_file', None)
        if p is None: # pragma: no cover
            log.warning("[%s] Skipping not existing default filter file", self.classifier)
            return

        r = os.path.join(log.configuration_path, p)

        if not os.path.exists(r): # pragma: no cover
            log.warning("[%s] Skipping not existing default filter file", self.classifier)
            return

        self._filters['namespace0'] = r
        self.filters = yara.compile(filepaths = self._filters)

    def add_rule(self, rule_file):
        if not os.path.exists(rule_file):
            log.warning("[%s] Skipping not existing classification rule file %s", self.classifier, rule_file)
            return

        self._rules["namespace{}".format(self.rules_namespace_id)] = rule_file
        self.rules_namespace_id += 1
        self.rules = yara.compile(filepaths = self._rules)

    def add_filter(self, filter_file):
        if not os.path.exists(filter_file):
            log.warning("[%s] Skipping not existing filter file %s", self.classifier, filter_file)
            return

        self._filters["namespace{}".format(self.filters_namespace_id)] = filter_file
        self.filters_namespace_id += 1
        self.filters = yara.compile(filepaths = self._filters)

    def discard_meta_domain_whitelist(self, url, values):
        p_url  = urlparse(url)
        netloc = p_url.netloc.split(':')[0].lower() # Remove the port from netloc, if present

        for value in values.split(','):
            domain = value.lower().strip()
            if not domain: # pragma: no cover
                continue

            prefix = "" if domain.startswith(".") else "."

            if netloc in (domain, ) or netloc.endswith("{}{}".format(prefix, domain)):
                log.warning("[discard_meta_domain_whitelist] Whitelisted domain: %s (URL: %s)", domain, url)
                return True

        return False

    def discard_url_match(self, url, match):
        for key, values in match.meta.items():
            m = getattr(self, "discard_meta_{}".format(key), None)
            if m and m(url, values): # pylint:disable=not-callable
                return True

        return False

    def add_customclassifier(self, method):
        if not callable(method):
            log.warning("Skipping non callable custom classifier %s", str(method))
            return

        get_function_code = operator.attrgetter("__code__")
        method_name = get_function_code(method).co_name
        self.custom_classifiers[method_name] = method.__get__(self)

    def reset_customclassifiers(self):
        self.custom_classifiers = dict()

    def handle_match_etags(self, match):
        etags = match.meta.get('etags', None)
        if etags is None:
            return

        _etags = [t.strip() for t in etags.split(',')]
        for s in match.strings:
            if s[1] not in _etags:
                continue

            tag = s[2].decode() if isinstance(s[2], bytes) else s[2]
            if tag not in match.tags:
                match.tags.append(tag)
