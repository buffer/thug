#!/usr/bin/env python

import os
import json
import tempfile
import logging
import requests
from myawis import *
import argparse
import urllib
from urlparse import urlparse
from bs4 import BeautifulSoup
import lxml
import six.moves.configparser as ConfigParser

parser = argparse.ArgumentParser()
parser.add_argument("url")
args = parser.parse_args()

class AwisQuery(object):
    def __init__(self):
        self.enabled = True
        self.opts    = dict()

        self.__init_config()

    def __init_config(self):
        config = ConfigParser.ConfigParser()

        conf_file = ('/etc/thug/awis.conf')

        config.read(conf_file)

        for option in config.options('AmazonWebInformationService'):
            self.opts[option] = config.get('AmazonWebInformationService', option)

        self.runtime_apikey = self.opts['apikey']

        self.runtime_secretkey = self.opts['secretkey']

        if not self.opts.get('apikey', None):
            self.enabled = False

        self.query()

    def query(self):
        url = args.url
        o = urlparse(url)
        awis_dict = {}
        obj = CallAwis(self.runtime_apikey, self.runtime_secretkey)
        urlinfo = obj.urlinfo(o.hostname)

        for trafficdata in urlinfo.findAll('TrafficData'):
            RANK = trafficdata.find('Rank').text
            if RANK == '':
                awis_dict['Site rank'] = 'empty'
            else:
                awis_dict['Site rank'] = RANK

        for contentdata in urlinfo.findAll('ContentData'):
            LINKS_IN_COUNT = contentdata.find('LinksInCount').text
            if LINKS_IN_COUNT == '':
                awis_dict['LinksInCount'] = 'empty'
            else:
                awis_dict['LinksInCount'] = LINKS_IN_COUNT

        for sitedata in urlinfo.findAll('SiteData'):
            if sitedata.find('Title'):
                TITLE = sitedata.find('Title').text
                awis_dict['Site title'] = TITLE
            else:
                awis_dict['Site title'] = 'empty'
            if sitedata.find('Description'):
                DESCRIPTION = sitedata.find('Description').text
                awis_dict['Site description'] = DESCRIPTION
            else:
                awis_dict['Site description'] = 'empty'
            if sitedata.find('OnlineSince'):
                ONLINE_SINCE = sitedata.find('OnlineSince').text
                awis_dict['OnlineSince'] = ONLINE_SINCE
            else:
                awis_dict['OnlineSince'] = 'empty'

        test = json.dumps(awis_dict)
        print(test)

AwisQuery()