#!/usr/bin/env python
#
# VirusTotal.py
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
import json
import tempfile
import logging
import requests
import six.moves.configparser as ConfigParser

log = logging.getLogger("Thug")


class VirusTotal(object):
    def __init__(self):
        self.enabled = True
        self.opts    = dict()

        self.__init_config()

    def __init_config(self):
        conf_file = os.path.join(log.configuration_path, 'thug.conf')
        if not os.path.exists(conf_file):
            log.warning("[WARNING] VirusTotal disabled (no configuration file found)")
            self.enabled = False
            return

        config = ConfigParser.ConfigParser()
        config.read(conf_file)

        for option in config.options('virustotal'):
            self.opts[option] = config.get('virustotal', option)

        runtime_apikey = log.ThugOpts.get_vt_runtime_apikey()
        if runtime_apikey: # pragma: no cover
            self.opts['apikey'] = runtime_apikey

        if not self.opts.get('apikey', None): # pragma: no cover
            self.enabled = False

    def save_report(self, response_dict, basedir, sample):
        log_dir = os.path.join(basedir, 'analysis', 'virustotal')
        content = json.dumps(response_dict)

        log.ThugLogging.log_virustotal(log_dir, sample, content)

        positives = str(response_dict.get("positives", {}))
        total     = str(response_dict.get("total", {}))

        log.warning("[VirusTotal] Sample %s analysis ratio: %s/%s", response_dict['md5'], positives, total)

    def get_report(self, report):
        params   = { "resource": report,
                     "allinfo" : 1,
                     "apikey"  : self.opts['apikey']}

        response = requests.get(self.opts["reporturl"], params = params)
        return response

    def query(self, sample, basedir):
        md5           = sample['md5']
        response      = self.get_report(md5)
        response_dict = response.json()
        response_code = response_dict.get(u"response_code")

        if response.ok:
            log.warning("[VirusTotal] %s", response_dict['verbose_msg'])

            if response_code == 1:
                self.save_report(response_dict, basedir, sample)
                return True

        return False # pragma: no cover

    def submit(self, data, sample):
        md5   = sample['md5']
        fd, s = tempfile.mkstemp()

        with open(s, "wb") as fd:
            fd.write(data)

        params   = {'apikey': self.opts['apikey']}
        files    = {'file'  : (md5, open(s, "rb"))}
        response = requests.post(self.opts["scanurl"], files = files, params = params)

        if response.ok:
            log.warning("[VirusTotal] Sample %s submitted", md5)

        os.remove(s)

    def analyze(self, data, sample, basedir):
        if not self.enabled:
            return

        if not self.opts['apikey']: # pragma: no cover
            return

        if sample.get('md5', None) and log.ThugOpts.vt_query and self.query(sample, basedir):
            return

        if log.ThugOpts.vt_submit: # pragma: no cover
            self.submit(data, sample)
