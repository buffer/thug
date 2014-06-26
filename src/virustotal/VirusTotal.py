import os
import sys
import errno
import json
import requests
import tempfile
import logging

log = logging.getLogger("Thug")

try:
    import configparser as ConfigParser
except ImportError:
    import ConfigParser

try:
    from io import StringIO
except ImportError:
    try:
        from cStringIO import StringIO
    except ImportError:
        from StringIO import StringIO


class VirusTotal(object):
    def __init__(self):
        self.enabled = True
        self.opts    = dict()

        self.__init_config()

    def __init_config(self):
        config = ConfigParser.ConfigParser()

        conf_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'virustotal.conf')
        if not os.path.isfile(conf_file):
            self.enabled = False
            return

        config.read(conf_file)

        for option in config.options('VirusTotal'):
            self.opts[option] = config.get('VirusTotal', option)

    def save_report(self, response_dict, basedir, md5):
        log_dir = os.path.join(basedir, 'analysis', 'virustotal')

        try:
            os.makedirs(log_dir)
        except OSError as e:
            if e.errno == errno.EEXIST:
                pass
            else:
                raise

        log_file = os.path.join(log_dir, '%s.json' % (md5, ))
        with open(log_file, 'w') as fd:
            fd.write(json.dumps(response_dict, indent = 4))

        positives = str(response_dict.get("positives", {}))
        total     = str(response_dict.get("total", {}))

        log.warning("[VirusTotal] Sample %s analysis ratio: %s/%s" % (response_dict['md5'], positives, total, )) 

    def get_report(self, report):
        params   = { "resource": report,
                     "allinfo" : 1, 
                     "apikey"  : self.opts['apikey']}

        response = requests.get(self.opts["reporturl"], params = params)
        return response

    def query(self, md5, basedir):
        response      = self.get_report(md5)
        response_dict = response.json()
        response_code = response_dict.get("response_code")

        if response.ok:
            if response_code == 1:
                self.save_report(response_dict, basedir, md5)
                return True
            
            log.warning("[VirusTotal] %s" % (response_dict['verbose_msg'], ))

        return False

    def submit(self, data, md5):
        sample = os.path.join(tempfile.gettempdir(), md5)

        with open(sample, "wb") as fd:
            fd.write(data)
        
        params   = {'apikey': self.opts['apikey']}
        files    = {'file'  : (md5, open(sample, "rb"))}
        response = requests.post(self.opts["scanurl"], files = files, params = params)
        
        if response.ok:
            log.warning("[VirusTotal] Sample %s submitted" % (md5, ))

        os.remove(sample)

    def analyze(self, data, md5, basedir):
        if not self.enabled:
            return

        if not self.opts['apikey']:
            return

        if md5 and log.ThugOpts.vt_query and self.query(md5, basedir):
            return

        if log.ThugOpts.vt_submit:
            self.submit(data, md5)
