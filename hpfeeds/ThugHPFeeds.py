#!/usr/bin/env python
#
# ThugHPFeeds.py
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
import sys
import time
import hashlib
import json
import logging
import threading
import ConfigParser
import hpfeeds


class ThugFiles(threading.Thread):
    def __init__(self, opts):
        self.opts = opts
        self.logging_init()
        threading.Thread.__init__(self)

    def logging_init(self):
        if self.opts['logdir'] is None:
            return

        if not os.path.exists(self.opts['logdir']):
            os.mkdir(self.opts['logdir'])
        
        self.log  = logging.getLogger("ThugFiles.HPFeeds")
        handler   = logging.FileHandler(os.path.join(self.opts['logdir'], 'thugfiles.log'))
        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s')
        handler.setFormatter(formatter)
        self.log.addHandler(handler)
        self.log.setLevel(logging.INFO)

    def run(self):
        def on_message(identifier, channel, payload):
            try: 
                decoded = json.loads(str(payload))
            except: 
                decoded = {'raw': payload}

            if not 'md5' in decoded or not 'data' in decoded:
                self.log.info("Received message does not contain hash or data - Ignoring it")
                return
            
            csv    = ', '.join(['{0} = {1}'.format(i, decoded[i]) for i in ['md5', 'sha1', 'type']])
            outmsg = 'PUBLISH channel = %s, identifier = %s, %s' % (channel, identifier, csv)
            self.log.info(outmsg)
  
            if self.opts['logdir'] is None:
                return

            filedata = decoded['data'].decode('base64')
            fpath = os.path.join(self.opts['logdir'], decoded['md5'])
            with open(fpath, 'wb') as fd:
                fd.write(filedata)

        def on_error(payload):
            self.log.critical("Error message from server: %s", payload)
            self.hpc.stop()

        while True:
            try:
                self.hpc = hpfeeds.new(self.opts['host'], int(self.opts['port']), self.opts['ident'], self.opts['secret'])
                self.log.info("Connected to %s", self.hpc.brokername)
                self.hpc.subscribe([self.opts['channel'], ])
            except hpfeeds.FeedException:
                break

            try:
                self.hpc.run(on_message, on_error)
            except:
                self.hpc.close()
                time.sleep(20)


class ThugEvents(threading.Thread):
    def __init__(self, opts):
        self.opts = opts
        self.logging_init()
        threading.Thread.__init__(self)

    def logging_init(self):
        if self.opts['logdir'] is None:
            return

        if not os.path.exists(self.opts['logdir']):
            os.mkdir(self.opts['logdir'])

        self.log  = logging.getLogger("ThugEvents.HPFeeds")
        handler   = logging.FileHandler(os.path.join(self.opts['logdir'], 'thugevents.log'))
        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s')
        handler.setFormatter(formatter)
        self.log.addHandler(handler)
        self.log.setLevel(logging.INFO)

    def run(self):
        def on_message(identifier, channel, payload):
            m = hashlib.md5()
            m.update(payload)

            outmsg = 'PUBLISH channel = %s, identifier = %s, MAEC = %s' % (channel, identifier, m.hexdigest())
            self.log.info(outmsg)

            if self.opts['logdir'] is None:
                return

            fpath = os.path.join(self.opts['logdir'], m.hexdigest())
            with open(fpath, 'wb') as fd: 
                fd.write(payload)
    
        def on_error(payload):
            self.log.critical("Error message from server: %s", payload)
            self.hpc.stop()

        while True:
            try:
                self.hpc = hpfeeds.new(self.opts['host'], int(self.opts['port']), self.opts['ident'], self.opts['secret'])
                self.log.info("Connected to %s", self.hpc.brokername)
                self.hpc.subscribe(self.opts['channel'])
            except hpfeeds.FeedException:
                break

            try:
                self.hpc.run(on_message, on_error)
            except:
                self.hpc.close()
                time.sleep(20)


class ThugHPFeeds(object):
    def __init__(self):
        self.events_opts  = dict()
        self.files_opts   = dict()
        self.config_init()

    def config_init(self):
        config = ConfigParser.ConfigParser()

        conf_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'hpfeeds.conf')
        config.read(conf_file)

        for option in config.options('HPFeeds'):
            opt = config.get('HPFeeds', option)
            self.events_opts[option] = opt
            self.files_opts[option]  = opt

        for option in config.options('ThugFiles'):
            self.files_opts[option] = config.get('ThugFiles', option)

        for option in config.options('ThugEvents'):
            self.events_opts[option] = config.get('ThugEvents', option)

    def run(self):
        if self.files_opts['enable']:
            files = ThugFiles(self.files_opts)
            files.start()
        
        if self.events_opts['enable']:
            events = ThugEvents(self.events_opts)
            events.start()
       

if __name__ == '__main__':
    try: 
        f = ThugHPFeeds()
        f.run()
    except KeyboardInterrupt:
        sys.exit(0)

