#!/usr/bin/env python
""" Thug Control

Send commands to Thug

"""

import json
import datetime
import argparse
import configparser

from urllib.parse import urlparse

import pika


class ThugCtrl(object):
    """ Thug remote control
    """

    def __init__(self, configfile, extensive = False, threshold = 0, referer = None, proxy = None, timeout = None):
        """ Init Thugd using config file
        """

        self.host = "localhost"
        self.queue = "thugctrl"
        self.username = "guest"
        self.password = "guest"
        self.extensive = extensive
        self.threshold = threshold
        self.referer = referer
        self.proxy = proxy
        self.timeout = timeout
        self.configfile = configfile
        self.read_config()

    def read_config(self):
        """ Read config from config file
        """

        conf = configparser.ConfigParser()
        conf.read(self.configfile)
        self.host = conf.get("jobs", "host")
        self.queue = conf.get("jobs", "queue")
        self.username = conf.get("credentials", "username")
        self.password = conf.get("credentials", "password")

    def send_command(self, data):
        credentials = pika.PlainCredentials(self.username, self.password)
        connection = pika.BlockingConnection(pika.ConnectionParameters(
            host=self.host, credentials = credentials))
        channel = connection.channel()

        channel.queue_declare(queue=self.queue, durable=True)

        message = json.dumps(data)
        channel.basic_publish(exchange='',
                              routing_key=self.queue,
                              body=message,
                              properties=pika.BasicProperties(
                                 delivery_mode=2,
                              ))
        print(" [x] Sent %r" % (message,))
        connection.close()

    def process(self, url):
        """ Send URL to process
        """

        if url.find("://") < 0:
            url = "http://" + url
        o = urlparse(url)

        jid = o.netloc + "_" + datetime.datetime.now().strftime(
            "%Y_%m_%d__%H_%M_%S")
        data = {"url": url,
                "id": jid,
                "threshold": self.threshold,
                "extensive": self.extensive,
                "referer": self.referer,
                "proxy": self.proxy,
                "timeout": self.timeout
                }
        print(data)

        self.send_command(data)


class ThugCollect(object):
    """ A class collecting thug results
    """

    def process(self, data):
        print(data)

    def callback(self, ch, method, properties, body):
        self.process(json.loads(body))
        ch.basic_ack(delivery_tag=method.delivery_tag)

    def __init__(self, configfile):

        self.configfile = configfile
        self.host = "localhost"
        self.queue = "thugctrl"
        self.rhost = "localhost"
        self.rqueue = "thugres"
        self.username = "guest"
        self.password = "guest"
        self.read_config()

        credentials = pika.PlainCredentials(self.username, self.password)
        connection = pika.BlockingConnection(pika.ConnectionParameters(
            host=self.rhost, credentials = credentials))
        channel = connection.channel()

        channel.queue_declare(queue=self.rqueue, durable=True)
        print(' [*] Waiting for messages on %s %s To exit press CTRL+C' % (
            self.rhost, self.rqueue))

        channel.basic_qos(prefetch_count=1)
        channel.basic_consume(lambda c, m, p, b: self.callback(c, m, p, b),
                              queue=self.rqueue)

        channel.start_consuming()

    def read_config(self):
        """ Read config from config file
        """

        conf = ConfigParser.ConfigParser()
        conf.read(self.configfile)
        self.host = conf.get("jobs", "host")
        self.queue = conf.get("jobs", "queue")

        self.rhost = conf.get("results", "host")
        self.rqueue = conf.get("results", "queue")

        self.username = conf.get("credentials", "username")
        self.password = conf.get("credentials", "password")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Send urls to Thug daemons tp process')
    parser.add_argument('--urls', type=str, nargs='+',
        help='One or more URLs to process')
    parser.add_argument('--config', help='Config file to use',
        default="config.ini")
    parser.add_argument('--collect_results',
        help='Start a daemon to collect the results',
        default=False, action="store_true")
    parser.add_argument('--extensive',
        help='In depth follow links',
        default=False, action="store_true")
    parser.add_argument('--threshold', type=int,
        help='Maximum pages to fetch',
        default=0)
    parser.add_argument('--referer', type=str,
        help='Referer to send',
        default=None)
    parser.add_argument('--proxy', type=str,
        help='Proxy to use',
        default=None)
    parser.add_argument('--timeout', type=int,
        help='Timeout in seconds for the analysis',
        default=None)

    args = parser.parse_args()

    if args.urls:
        t = ThugCtrl(args.config, args.extensive, args.threshold, args.referer, args.proxy, args.timeout)
        for aurl in args.urls:
            t.process(aurl)

    if args.collect_results:
        res = ThugCollect(args.config)
