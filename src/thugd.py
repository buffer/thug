#!/usr/bin/env python
"""
Thug daemon

By thorsten.sick@avira.com
For the iTES project (www.ites-project.org)
"""

import argparse
import pika
import sys
import time
import json
from ConfigParser import ConfigParser
import subprocess
import os
import shutil


class Thugd():
    """ A class waiting for jobs, starting thug, returning results
    """

    def runProcess(self, exe):
        p = subprocess.Popen(exe, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)
        while(True):
            retcode = p.poll()
            line = p.stdout.readline()
            yield line
            if(retcode is not None):
                break

    def send_results(self, data):
        connection = pika.BlockingConnection(pika.ConnectionParameters(
        host=self.rhost))
        channel = connection.channel()

        channel.queue_declare(queue=self.rqueue, durable=True)

        message = json.dumps(data)
        channel.basic_publish(exchange='',
                              routing_key=self.rqueue,
                              body=message,
                              properties=pika.BasicProperties(
                                 delivery_mode=2,
                              ))
        print " [x] Sent %r" % (message,)
        connection.close()

    def copy_to_result(self, frompath, job):
        """ Copy result folder to result path
        """

        if not frompath:
            return None
        respath = os.path.join(self.resdir, str(job["id"]))
        shutil.copytree(frompath, respath)
        return os.path.relpath(respath, self.resdir)

    def process(self, job):
        """ Execute thug to process a job
        """
        print "job" + str(job)
        command = ["python", "thug.py", "-t", str(job["threshold"])]
        if job["extensive"]:
            command.append("-E")
        if job["timeout"]:
            command.append("-T")
            command.append(str(job["timeout"]))
        if job["referer"]:
            command.append("-r")
            command.append(job["referer"])
        if job["proxy"]:
            command.append("-p")
            command.append(job["proxy"])
        command.append(job["url"])
        print command
        pathname = None
        for line in self.runProcess(command):
            if line.startswith("["):
                print line,
            if line.find("] Saving log analysis at ") >= 0:
                pathname = line.split(" ")[-1].strip()
        rpath = self.copy_to_result(pathname, job)
        res = {"id": job["id"],
               "rpath": rpath}
        self.send_results(res)

    def callback(self, ch, method, properties, body):
        print " [x] Received %r" % (body,)
        if not self.clear:
            self.process(json.loads(body))
        print " [x] Done"
        ch.basic_ack(delivery_tag=method.delivery_tag)

    def read_config(self):
        """ Read config from config file
        """

        conf = ConfigParser()
        conf.read(self.configfile)
        self.host = conf.get("jobs", "host")
        self.queue = conf.get("jobs", "queue")

        self.rhost = conf.get("results", "host")
        self.rqueue = conf.get("results", "queue")

        self.resdir = conf.get("results", "resdir")

    def __init__(self, configfile, clear=False):
        """
        @configfile: The configfile to use
        @clear: clear the job chain
        """

        self.configfile = configfile
        self.clear = clear
        self.host = "localhost"
        self.queue = "thugctrl"
        self.rhost = "localhost"
        self.rqueue = "thugres"
        self.read_config()

        connection = pika.BlockingConnection(pika.ConnectionParameters(
            host=self.host))
        channel = connection.channel()

        channel.queue_declare(queue=self.queue, durable=True)
        print ' [*] Waiting for messages on %s %s To exit press CTRL+C' % (
            self.host, self.queue)

        channel.basic_qos(prefetch_count=1)
        channel.basic_consume(lambda c, m, p, b: self.callback(c, m, p, b),
                              queue=self.queue)

        channel.start_consuming()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Receives jobs and starts Thug to process them')
    parser.add_argument('--config', help='Config file to use',
        default="config.ini")
    parser.add_argument('--clear', help='Clear the job chain',
        default=False, action="store_true")

    args = parser.parse_args()

    t = Thugd(args.config, args.clear)
