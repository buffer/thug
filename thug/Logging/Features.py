#!/usr/bin/env python
#
# Features.py
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


class Features(object):
    counters = (
        'activex_count',
        'addeventlistener_count',
        'alert_count',
        'appendchild_count',
        'attachevent_count',
        'body_count',
        'characters_count',
        'clonenode_count',
        'createdocumentfragment_count',
        'createelement_count',
        'data_uri_count',
        'detachevent_count',
        'dispatchevent_count',
        'document_write_count',
        'embed_count',
        'embed_string_count',
        'eval_count',
        'external_javascript_count',
        'external_javascript_characters_count',
        'external_javascript_whitespaces_count',
        'form_string_count',
        'frame_string_count',
        'getcomputedstyle_count',
        'head_count',
        'hidden_count',
        'html_count',
        'iframe_count',
        'iframe_small_width_count',
        'iframe_small_height_count',
        'iframe_small_area_count',
        'iframe_string_count',
        'inline_javascript_count',
        'inline_javascript_characters_count',
        'inline_javascript_whitespaces_count',
        'inline_vbscript_count',
        'inline_vbscript_characters_count',
        'inline_vbscript_whitespaces_count',
        'insertbefore_count',
        'meta_refresh_count',
        'noscript_count',
        'object_count',
        'object_small_width_count',
        'object_small_height_count',
        'object_small_area_count',
        'object_string_count',
        'removeattribute_count',
        'removechild_count',
        'removeeventlistener_count',
        'replacechild_count',
        'setattribute_count',
        'setinterval_count',
        'settimeout_count',
        'title_count',
        'url_count',
        'whitespaces_count'
    )

    def __init__(self):
        self.features = dict()

    def __getattr__(self, key):
        if key.startswith('increase_'):
            counter = key.split('increase_')[1]

            if counter in self.counters:
                return lambda: self.increase(counter)

        if key.startswith('add_'):
            counter = key.split('add_')[1]

            if counter in self.counters:
                return lambda value: self.add(counter, value)

        raise AttributeError # pragma: no cover

    def clear(self):
        self.features = dict()

    def init_features(self, url):
        if url in self.features:
            return

        self.features[url] = dict()
        for counter in self.counters:
            self.features[url][counter] = 0

    @property
    def features_url(self):
        if log.ThugOpts.local:
            return log.ThugLogging.url

        url = getattr(log, 'last_url', None)
        return url if url else log.DFT.window.url

    def increase(self, key):
        if not log.ThugOpts.features_logging: # pragma: no cover
            return

        url = self.features_url
        self.init_features(url)
        self.features[url][key] += 1

    def add(self, key, value):
        if not log.ThugOpts.features_logging: # pragma: no cover
            return

        url = self.features_url
        self.init_features(url)
        self.features[url][key] += value
