#!/usr/bin/env python
"""
Thug daemon

By thorsten.sick@avira.com
For the iTES project (www.ites-project.org)
"""

import os
import sys
import json
import shutil
import argparse
import subprocess
import configparser

import pika


class Thugd(object):
    """
        A class waiting for jobs, starting thug, returning results
    """
    def __init__(self, configfile, clear = False):
        """
        @configfile:    The configuration file to use
        @clear:         Clear the job chain
        """

        self.clear = clear
        self.username = "guest"
        self.password = "guest"
        self._read_config(configfile)
        self._chdir()
        self._run_queue()

    def _read_config(self, configfile):
        """
        read_config

        Read configuration from configuration file

        @configfile: The configfile to use
        """
        self.host   = "localhost"
        self.queue  = "thugctrl"
        self.rhost  = "localhost"
        self.rqueue = "thugres"

        if configfile is None:
            return

        conf = configparser.ConfigParser()
        conf.read(configfile)
        self.host = conf.get("jobs", "host")
        self.queue = conf.get("jobs", "queue")
        self.rhost = conf.get("results", "host")
        self.rqueue = conf.get("results", "queue")
        self.resdir = conf.get("results", "resdir")
        self.username = conf.get("credentials", "username")
        self.password = conf.get("credentials", "password")

    def _chdir(self):
        os.chdir(os.path.abspath(os.path.join(os.path.dirname(__file__),
                                              os.pardir,
                                              os.pardir,
                                              'src')))

    def _run_queue(self):
        credentials = pika.PlainCredentials(self.username, self.password)
        parameters = pika.ConnectionParameters(host = self.host, credentials = credentials)
        connection = pika.BlockingConnection(parameters)
        channel = connection.channel()

        channel.queue_declare(queue = self.queue, durable = True)
        print("[*] Waiting for messages on %s %s (press CTRL+C to exit)" % (self.host, self.queue, ))

        channel.basic_qos(prefetch_count = 1)
        channel.basic_consume(lambda c, m, p, b: self.callback(c, m, p, b), queue = self.queue)
        channel.start_consuming()

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
        credentials = pika.PlainCredentials(self.username, self.password)
        parameters = pika.ConnectionParameters(host = self.rhost, credentials = credentials)
        connection = pika.BlockingConnection(parameters)
        channel = connection.channel()

        channel.queue_declare(queue = self.rqueue, durable = True)

        message = json.dumps(data)
        channel.basic_publish(exchange    = '',
                              routing_key = self.rqueue,
                              body        = message,
                              properties  = pika.BasicProperties(delivery_mode = 2,))

        print("[x] Sent %r" % (message,))
        connection.close()

    def copy_to_result(self, frompath, job):
        """
        Copy result folder to result path
        """

        if not frompath:
            return None

        respath = os.path.join(self.resdir, str(job["id"]))
        shutil.copytree(frompath, respath)
        return os.path.relpath(respath, self.resdir)

    def process(self, job):
        """
        Execute thug to process a job
        """
        print("job" + str(job))
        print(os.getcwd())

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
        print(command)

        pathname = None

        for line in self.runProcess(command):
            if line.startswith("["):
                print(line, end = " ")

            if line.find("] Saving log analysis at ") >= 0:
                pathname = line.split(" ")[-1].strip()

        rpath = self.copy_to_result(pathname, job)
        res = {"id"     : job["id"],
               "rpath"  : rpath}

        self.send_results(res)

    def callback(self, ch, method, properties, body):
        print("[x] Received %r" % (body, ))

        if not self.clear:
            self.process(json.loads(body))

        print("[x] Done")

        ch.basic_ack(delivery_tag=method.delivery_tag)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = 'Receives jobs and starts Thug to process them')
    parser.add_argument('--config', help = 'Configuration file to use', default = "config.ini")
    parser.add_argument('--clear', help = 'Clear the job chain', default = False, action = "store_true")
    args = parser.parse_args()

    try:
        t = Thugd(args.config, args.clear)
    except KeyboardInterrupt:
        sys.exit(0)
