#!/usr/bin/env python

import os
import logging
import configparser

from urllib.parse import urlparse

MYAWIS_MODULE = True

try:
    import myawis
except ImportError:
    MYAWIS_MODULE = False

log = logging.getLogger("Thug")


class AWIS:
    def __init__(self):
        self.enabled = MYAWIS_MODULE
        self.__init_awis()

    def __init_awis(self):
        self._awis_api = None

        if not self.enabled:
            return

        conf_file = os.path.join(log.configuration_path, 'thug.conf')
        if not os.path.exists(conf_file):
            self.enabled = False
            return

        config = configparser.ConfigParser()
        config.read(conf_file)

        enable = config.getboolean('awis', 'enable')
        if not enable:
            self.enabled = False
            return

        self.apikey = config.get('awis', 'apikey')
        self.secretkey = config.get('awis', 'secretkey')

    @property
    def awis_api(self):
        if not self.enabled:
            log.warning("[AWIS] Analysis subsystem disabled")
            return None

        if not self._awis_api:
            self._awis_api = myawis.CallAwis(self.apikey, self.secretkey)

        return self._awis_api

    def query(self, url):
        result = dict()

        if not log.ThugOpts.awis:
            return result

        if not url:
            return result

        if not self.awis_api:
            return result

        p_url = urlparse(url)
        hostname = p_url.hostname
        if not hostname:
            return result

        result['url'] = url
        result['hostname'] = hostname

        urlinfo = self.awis_api.urlinfo(hostname)

        for trafficdata in urlinfo.findAll('TrafficData'):
            rank = trafficdata.find('Rank')
            result['SiteRank'] = rank.text if rank else str()
            log.warning("[AWIS][Host: %s] SiteRank: %s", hostname, result['SiteRank'])

        for contentdata in urlinfo.findAll('ContentData'):
            links = contentdata.find('LinksInCount')
            result['LinksInCount'] = links.text if links else str()
            log.warning("[AWIS][Host: %s] LinksInCount: %s", hostname, result['LinksInCount'])

            for sitedata in contentdata.findAll('SiteData'):
                title = sitedata.find('Title')
                result['SiteTitle'] = title.text if title else str()
                log.warning("[AWIS][Host: %s] SiteTitle: %s", hostname, result['SiteTitle'])

                description = sitedata.find('Description')
                result['SiteDescription'] = description.text if description else str()
                log.warning("[AWIS][Host: %s] SiteDescription: %s", hostname, result['SiteDescription'])

                onlinesince = sitedata.find('OnlineSince')
                result['OnlineSince'] = onlinesince.text if onlinesince else str()
                log.warning("[AWIS][Host: %s] OnlineSince: %s", hostname, result['OnlineSince'])

            for adultcontent in contentdata.findAll('AdultContent'):
                result['AdultContent'] = adultcontent.text if adultcontent else str()
                log.warning("[AWIS][Host: %s] AdultContent: %s", hostname, result['AdultContent'])

        return result
