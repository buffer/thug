#!/usr/bin/env python
#
# SampleClassifier.py
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
#
# Original code written by Thorsten Sick <thorsten.sick@avira.com>
# from Avira (developed for the iTES Project http://ites-project.org)
#
# Modified by Angelo Dell'Aera:
#   - Designed the more generic Classifier module and embedded this
#     module into such module
#   - Converted to YARA rules

import logging
from .BaseClassifier import BaseClassifier

log = logging.getLogger("Thug")


class SampleClassifier(BaseClassifier):
    default_rule_file   = "rules/sampleclassifier.yar"
    default_filter_file = "rules/samplefilter.yar"
    classifier          = "Sample Classifier"

    def __init__(self):
        BaseClassifier.__init__(self)

    def classify(self, sample, md5):
        for match in self.rules.match(data = sample):
            self.matches.append((sample, match))

            rule = match.rule
            tags = ", ".join([" ".join(t.split('_')) for t in match.tags])
            log.ThugLogging.log_classifier("sample", md5, rule, tags)

        for c in self.custom_classifiers:
            self.custom_classifiers[c](sample, md5)

    def filter(self, sample, md5):
        ret = False

        for match in self.filters.match(data = sample):
            rule = match.rule
            tags = ", ".join([" ".join(t.split('_')) for t in match.tags])
            log.ThugLogging.log_classifier("samplefilter", md5, rule, tags)
            ret = True

        return ret
