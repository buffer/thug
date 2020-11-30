.. _docker:

Docker
======

If you want to run up a quick instance of Thug on a couple of malicious web sites or try 
it out but just lack the knowledge and/or time to install it, an alternative exists. Thanks 
to Docker you can run Thug up in a matter of minutes. 

Currently there exist a few docker images in the Docker Hub ready to run.

Docker is a platform for developers and sysadmins to develop, ship, and run applications. 
Docker lets you quickly assemble applications from components and eliminates the friction 
that can come when shipping code. Docker lets you get your code tested and deployed into 
production as fast as possible.

Docker consists of:

* The Docker Engine - a lightweight and powerful open source container virtualization 
  technology combined with a work flow for building and containerizing your applications.
* Docker Hub - a SaaS service for sharing and managing application stacks.


Installation
------------

Please refer to http://docs.docker.com/installation/#installation for instructions on how
to install Docker on your system. 

For instance on Debian/Ubuntu systems you just need to run the following commands 

.. code-block:: sh

    $ sudo apt-get update
    $ sudo apt-get install docker.io

After Docker is properly installed you can proceed with the Thug installation. Get the 
dockerized Thug from the Honeynet Project's Docker repository at https://hub.docker.com/r/buffer/thug

Thug will be installed in the directory */opt/thug*. To run it just execute *python /opt/thug/src/thug.py [options] URL*.

Download the latest stable container

.. code-block:: sh

    $ docker pull buffer/thug

Then mount your host ~/logs dir and enable it to keep the logs on the host

.. code-block:: sh

    $ docker run -it -v ~/logs:/logs buffer/thug

Test the dockerized Thug inside the container analyzing 20 random samples

.. code-block:: sh

    $ for item in $(find /opt/thug/samples/ -type f | xargs shuf -e |tail -n 20); do python /opt/thug/src/thug.py -l $item; done

If everything works fine just enjoy your new Thug instance!
