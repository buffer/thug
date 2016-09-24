#!/usr/bin/env python
#
# HoneyAgent.py
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
import base64
import requests
import tempfile
import logging

log = logging.getLogger("Thug")

try:
    import configparser as ConfigParser
except ImportError:
    import ConfigParser


class HoneyAgent(object):
    def __init__(self):
        self.enabled = True
        self.opts    = dict()

        self.__init_config()

    def __init_config(self):
        config = ConfigParser.ConfigParser()

        conf_file = os.path.join(log.configuration_path, 'honeyagent.conf')

        if not os.path.isfile(conf_file):
            self.enabled = False
            return

        config.read(conf_file)

        for option in config.options('HoneyAgent'):
            self.opts[option] = config.get('HoneyAgent', option)

    def save_report(self, response, basedir, sample):
        log_dir  = os.path.join(basedir, 'analysis', 'honeyagent')
        log.ThugLogging.log_honeyagent(log_dir, sample, response.text)

    def save_dropped(self, response, basedir, sample):
        data = response.json()

        result = data.get("result", None)
        if result is None:
            return None

        files = result.get("files", None)
        if files is None:
            return result

        md5 = sample['md5']
        log_dir = os.path.join(basedir, 'analysis', 'honeyagent', 'dropped')

        for filename in files.keys():
            log.warning("[HoneyAgent][%s] Dropped sample %s", md5, os.path.basename(filename))
            data = base64.b64decode(files[filename])
            log.ThugLogging.store_content(log_dir, os.path.basename(filename), data)
            log.ThugLogging.log_file(data)

        return result

    def dump_yara_analysis(self, result, sample):
        yara = result.get("yara", None)
        if yara is None:
            return

        md5 = sample['md5']

        for key in yara.keys():
            for v in yara[key]:
                log.warning("[HoneyAgent][%s] Yara %s rule %s match", md5, key, v['rule'])

    def submit(self, data, sample, params):
        md5    = sample['md5']
        sample = os.path.join(tempfile.gettempdir(), md5)

        with open(sample, "wb") as fd:
            fd.write(data)
       
        files    = {'file'  : (md5, open(sample, "rb"))}
        response = requests.post(self.opts["scanurl"], files = files, params = params)
        
        if response.ok:
            log.warning("[HoneyAgent][%s] Sample submitted", md5)

        os.remove(sample)
        return response

    def analyze(self, data, sample, basedir, params):
        if not self.enabled:
            return

        if not log.ThugOpts.honeyagent:
            return

        if params is None:
            params = dict()

        response = self.submit(data, sample, params)
        self.save_report(response, basedir, sample)
        result = self.save_dropped(response, basedir, sample)
        if result:
            self.dump_yara_analysis(result, sample)
