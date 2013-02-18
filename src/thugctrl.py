#!/usr/bin/env python
""" Thug Control

Send commands to Thug

"""

import argparse
import pika
import sys
import json
from ConfigParser import ConfigParser
from urlparse import urlparse
import datetime


class ThugCtrl():
    """ Thug remote control
    """

    def __init__(self, configfile):
        """ Init Thugd using config file
        """

        self.host = "localhost"
        self.queue = "thugctrl"
        self.configfile = configfile
        self.read_config()

    def read_config(self):
        """ Read config from config file
        """

        conf = ConfigParser()
        conf.read(self.configfile)
        self.host = conf.get("jobs", "host")
        self.queue = conf.get("jobs", "queue")

    def send_command(self, data):
        connection = pika.BlockingConnection(pika.ConnectionParameters(
        host=self.host))
        channel = connection.channel()

        channel.queue_declare(queue=self.queue, durable=True)

        message = json.dumps(data)
        channel.basic_publish(exchange='',
                              routing_key=self.queue,
                              body=message,
                              properties=pika.BasicProperties(
                                 delivery_mode=2,
                              ))
        print " [x] Sent %r" % (message,)
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
                }
        print data

        self.send_command(data)


class ThugCollect():
    """ A class collecting thug results
    """

    def process(self, data):
        print data

    def callback(self, ch, method, properties, body):
        self.process(json.loads(body))
        ch.basic_ack(delivery_tag=method.delivery_tag)

    def __init__(self, configfile):

        self.configfile = configfile
        self.host = "localhost"
        self.queue = "thugctrl"
        self.rhost = "localhost"
        self.rqueue = "thugres"
        self.read_config()

        connection = pika.BlockingConnection(pika.ConnectionParameters(
            host=self.rhost))
        channel = connection.channel()

        channel.queue_declare(queue=self.rqueue, durable=True)
        print ' [*] Waiting for messages on %s %s To exit press CTRL+C' % (
            self.rhost, self.rqueue)

        channel.basic_qos(prefetch_count=1)
        channel.basic_consume(lambda c, m, p, b: self.callback(c, m, p, b),
                              queue=self.rqueue)

        channel.start_consuming()

    def read_config(self):
        """ Read config from config file
        """

        conf = ConfigParser()
        conf.read(self.configfile)
        self.host = conf.get("jobs", "host")
        self.queue = conf.get("jobs", "queue")

        self.reshost = conf.get("results", "host")
        self.rqueue = conf.get("results", "queue")


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

    args = parser.parse_args()

    if args.urls:
        t = ThugCtrl(args.config)
        for aurl in args.urls:
            t.process(aurl)

    if args.collect_results:
        res = ThugCollect(args.config)
