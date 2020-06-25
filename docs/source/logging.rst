.. _logging:

Logging
*******

Currently different logging modes are available in Thug. Some of them can be combined
in order to store the result of the analysis in different formats if needed. By default
Thug attempts storing analysis logs in a MongoDB instance (see later for a detailed
explanation of the MongoDB collection schema).

The available logging modes are:

* MongoDB logging mode
* ElasticSearch
* JSON logging mode
* File logging mode


Logging configuration
=====================

The configuration file */etc/thug/thug.conf* defines the way Thug uses to log the results
of its analyses. The default logging configuration is shown below.

.. code-block:: sh

    [mongodb]
    enable:     false
    host:       localhost
    port:       27017

    [elasticsearch]
    enable:     false
    url:        http://192.168.56.101:9200
    index:      thug


The different sections of the configuration files will be explained later in this 
document.

MongoDB logging mode
====================

By default Thug attempts storing the result of its analyses in a MongoDB instance. Be
aware that if you don't install MongoDB and pymongo (the Python wrapper) or if the 
MongoDB process is not running, Thug will just emit a warning message and then continue 
its analysis silently not storing the results. This could be exactly what you want but 
please consider that if you do not enable any other logging mode you will end up with 
no logs at all so bear it in mind.

The configuration file */etc/thug/thug.conf* defines the MongoDB instance configuration
parameters

.. code-block:: sh

    [mongodb]
    enable:     True
    host:       localhost
    port:       27017

The parameters should be quite intuitive to understand. By the way if you install 
MongoDB on the same host you are supposed to run Thug you should not need changing
anything in the default configuration.

If you want Thug to store its results to a different MongoDB instance than that defined
in your */etc/thug/thug.conf* file, you can specify a different address at runtime, for
example by using the *--mongodb-address* option from the command line. This can be especially
useful when using the dockerized version of Thug, where storing results in Docker itself would
mean to lose them as soon as the Docker instance is shut down.


Collection schema
-----------------

urls
^^^^

The collection *urls* is used to keep track of the URLs visited during the analysis.
A URL is always associated a single entry in this collection even if it is visited 
multiple times (during the same analysis or in different analyses). Associating a 
unique ObjectID to a given URL allows to easily spot interesting scenarios like 
different redirection chains ending up using the same URLs. 

.. code-block:: sh

        { 
            "url" : URL
        }

analyses
^^^^^^^^

The collection *analyses* is used to keep track of the Thug analyses. The analysis
options used for the single analysis are stored together with other useful information 
like the used Thug version and the analysis datetime. Moreover the URL ObjectID of the 
initial URL is stored for convenience.

.. code-block:: sh


        { 
            "url_id"      : Initial URL url_id
            "timestamp"   : Analysis datetime
            "thug"        : {
                                "version"            : Thug version
                                "personality" : { 
                                    "useragent"      : User Agent
                                },
                                "plugins" : { 
                                    "acropdf"        : Acrobat Reader version (if any)
                                    "javaplugin"     : JavaPlugin version (if any)
                                    "shockwaveflash" : Shockwave Flash version (if any)
                                },
                                "options" : { 
                                    "local"          : Local analysis
                                    "nofetch"        : Local no-fetch analysis
                                    "proxy"          : Proxy (if any)
                                    "events"         : Additional DOM events to be processed
                                    "delay"          : Maximum setTimeout/setInterval delay value (in milliseconds)
                                    "referer"        : Referer
                                    "timeout"        : Analysis timeout
                                    "threshold"      : Maximum pages to fetch
                                    "extensive"      : Extensive fetch of linked pages
                                },
                            }
        }

connections
^^^^^^^^^^^

The collection *connections* is used to keep track of the redirections which could happen
during the single analysis. The field *chain_id* is a counter which is incremented by one at 
every redirection and it's meant to be used in order to rebuild the redirection chain in the 
right order while analyzing data.

.. code-block:: sh

        { 
            "analysis_id"    : Analysis ID
            "chain_id"       : Chain ID
            "source_id"      : Source URL url_id
            "destination_id" : Destination URL url_id
            "method"         : Method
            "flags"          : Flags
        }

locations
^^^^^^^^^

The collection *locations* is used to keep track of the content stored at each URL visited
during the analysis. The content is stored in a MongoDB GridFS and additional metadata are 
saved like MD5 and SHA-256 checksums, content size, content type (as served by the server)
and evaluated content type.

.. code-block:: sh


        { 
            "analysis_id"   : Analysis ID
            "url_id"        : URL url_id
            "status"        : HTTP status code
            "content_id"    : Content ID (content stored in the GridFS fs)
            "content-type"  : Content Type
            "md5"           : MD5 checksum
            "sha256"        : SHA-256 checksum
            "ssdeep"        : Ssdeep hash
            "flags"         : Flags
            "size"          : Data size
            "mime-type"     : Evaluated content type
        }

samples
^^^^^^^

The collection *samples* is used to keep track of the downloaded samples (currently supported 
types: PE, PDF, JAR and SWF). The sample itself is stored in a MongoDB GridFS and additional 
metadata are saved like MD5, SHA-1 and SHA-256 checksums, sample type and imphash (if the sample
type is PE).

.. code-block:: sh

        { 
            "analysis_id"   : Analysis ID
            "url_id"        : URL url_id
            "sample_id"     : Sample ID (sample stored in the GridFS fs)
            "type"          : Sample type
            "md5"           : MD5 checksum
            "sha1"          : SHA-1 checksum
            "sha256"        : SHA-256 checksum
            "imphash"       : Imphash (if type is PE)
        }

exploits
^^^^^^^^

The collection *eploits* is used to keep track of the exploits which were successfully 
identified during the analysis while visiting the URL referenced by *url_id*.

.. code-block:: sh

        {
            'analysis_id' : Analysis ID
            'url_id'      : URL url_id
            'module'      : Module/ActiveX Control, etc. that gets exploited
            'description' : Description of the exploit
            'cve'         : CVE number (if available)
            'data'        : Additional information
        }

classifiers
^^^^^^^^^^^

The collection *classifiers* is used to keep track of the Thug classifiers matches that
fire during the analysis while visiting the URL referenced by *url_id*.

.. code-block:: sh

        {
            'analysis_id' : Analysis ID
            'url_id'      : URL url_id
            'classifier'  : Classifier name (possible values: html, js, url, sample)
            'rule'        : Rule name
            'tags'        : Rule tags
        }

codes
^^^^^

The collection *codes* is used to keep track of the (dynamic language) snippets of code 
identified during the analysis.

.. code-block:: sh

        {
            'analysis_id'  : Analysis ID
            'snippet'      : Code snippet
            'language'     : Code language
            'relationship' : Relationship with the page that references the code
            'tag'          : Snippet tag (cross-references)
            'method'       : Analysis method
        }

behaviors
^^^^^^^^^

The collection *behaviors* is used to keep track of the suspicious and/or malicious 
behaviors observed during the analysis.

.. code-block:: sh

        {
            'analysis_id' : Analysis ID
            'description' : Observed behavior description 
            'cve'         : CVE number (if available)
            'snippet'     : Code snippet tag (if available)
            'method'      : Analysis method
            'timestamp'   : Timestamp
        }

certificates
^^^^^^^^^^^^

The collection *certificates* is used to store the SSL certificates collected from
servers during the analysis.

.. code-block:: sh

        {
            "analysis_id"   : Analysis ID
            "url_id"        : URL url_id
            "certificate"   : SSL certificate
        }

graphs
^^^^^^

The collection *graphs* is used to store the analysis JSON exploit graph.  

.. code-block:: sh

        {
            "analysis_id"   : Analysis ID
            "graph"         : JSON exploit graph
        }

virustotal
^^^^^^^^^^

The collection *virustotal* is used to store the VirusTotal sample analysis reports.
The Sample ObjectID references the *samples* collection.

.. code-block:: sh

        {
            "analysis_id"   : Analysis ID
            "sample_id"     : Sample ID
            "report"        : VirusTotal report (JSON)
        }

honeyagent
^^^^^^^^^^

The collection *honeyagent* is used to store the HoneyAgent Java sandbox sample analysis
reports. The Sample ObjectID references the *samples* collection.

.. code-block:: sh

        {
            "analysis_id"   : Analysis ID
            "sample_id"     : Sample ID
            "report"        : HoneyAgent report (JSON)
        }

json
^^^^

The collection *json* is used to store the Thug analysis reports in JSON format. 
JSON logging mode should be enabled in order to have Thug saving data in
this collection

.. code-block:: sh

    {
            "analysis_id"   : Analysis ID
            "report"        : Analysis report (JSON)
    }


images
^^^^^^

The collection *images* is used to store the results of the image processing
analysis.

.. code-block:: sh

    {
            "analysis_id"   : Analysis ID
            "url_id"        : URL url_id
            "classifier"    : Classifier (possible values: OCR)
            "result"        : Analysis result
    }


screenshots
^^^^^^^^^^^

The collection *screenshots* is used to store base-64 encoded screenshots (JPG format)
of the analyzed page.

.. code-block:: sh

   {
            "analysis_id"   : Analysis ID
            "url_id"        : URL url_id
            "screenshot"    : URL screenshot
    }


awis
^^^^

The collection *awis* is used to store Alexa Web Information Service (AWIS) reports.

.. code-block:: sh

    {
            "analysis_id"   : Analysis ID
            "report"        : AWIS report
    }


ElasticSearch logging module
============================

The ElasticSearch logging mode allows to store both the analysis results and each resource
downloaded during the analysis in an ElasticSearch instance. Deploying and configuring the
instance is totally up to you and no images are provided for that. 

Starting from Thug version 1.6 you are required to install Python ElasticSearch Client by
yourself. The reason behind this choice is that you could be interested in installing a
specific library version based on the ElasticSearch version you are using. Please look at
`Python ElasticSearch Client documentation <https://elasticsearch-py.readthedocs.io/en/master/>`_
for additional details.

ElasticSearch logging mode is not enabled by default and you need to enable the option -G 
(--elasticsearch-logging). The ElasticSearch configuration is saved in the */etc/thug/thug.conf*
file. Be sure of defining the right URL for connecting to your instance. You may want to
change the index name where data will be stored but this is not really necessary in the most 
common situations.

.. code-block:: sh

    [elasticsearch]
    enable:     True
    url:        http://192.168.56.101:9200
    index:      thug


JSON logging mode
=================

The JSON logging mode allows to store both the analysis results and each resource
downloaded during the analysis in JSON format. The JSON logging mode was enabled by default
before Thug 0.5.6 together with the File logging mode. If you are using Thug 0.5.7 (or later) 
you have to explicitely enable it through the option *-Z* (or *--json-logging*). Please consider 
that the JSON log is stored in the MongoDB instance (if available). See the *MongoDB logging 
mode* for details. If the File logging format is enabled too, the JSON log will be stored
in a JSON file in the log directory too. The JSON format is shown below.

.. code-block:: sh

    {
        "url"         : Initial URL
        "timestamp"   : Analysis datetime
        "logtype"     : "json-log",
        "thug"        : {
                            "version"            : Thug version
                            "personality" : {
                                    "useragent"      : User Agent
                            },
                            "plugins" : {
                                    "acropdf"        : Acrobat Reader version (if any)
                                    "javaplugin"     : JavaPlugin version (if any),
                                    "shockwaveflash" : Shockwave Flash version (if any)
                            },
                            "options" : { 
                                    "local"          : Local analysis
                                    "nofetch"        : Local no-fetch analysis
                                    "proxy"          : Proxy (if any)
                                    "events"         : Additional DOM events to be processed
                                    "delay"          : Maximum setTimeout/setInterval delay value (in milliseconds)
                                    "referer"        : Referer
                                    "timeout"        : Analysis timeout
                                    "threshold"      : Maximum pages to fetch
                                    "extensive"      : Extensive fetch of linked pages
                            },
        "behavior"    : [],
        "code"        : [],
        "files"       : [],
        "connections" : [],
        "locations"   : [],
        "exploits"    : [],
        "classifiers" : [],
        "images"      : [],
        "awis"        : [],
        "screenshots" : []
    }


Following the format and additional details about the lists containing the analysis results
and the resources downloaded during the analysis. 


behaviors
---------

.. code-block:: sh

        {
            'description' : Observed behavior description 
            'cve'         : CVE number (if available)
            'snippet'     : Code snippet tag (if available)
            'method'      : Analysis method
            'timestamp'   : Timestamp
        }


codes
-----

.. code-block:: sh

        {
            'snippet'      : Code snippet
            'language'     : Code language
            'relationship' : Relationship with the page that references the code
            'tag'          : Snippet tag (cross-references)
            'method'       : Analysis method
        }


files
-----

Each content downloaded during the analysis is saved in an entry in the *files*
list.


connections
-----------

.. code-block:: sh

        { 
            "source"         : Source URL
            "destination"    : Destination URL
            "method"         : Method
            "flags"          : Flags
        }


locations
---------

.. code-block:: sh


        { 
            "url"           : URL url
            "content"       : Content
            "status"        : HTTP status code
            "content-type"  : Content Type
            "md5"           : MD5 checksum
            "sha256"        : SHA-256 checksum
            "ssdeep"        : Ssdeep hash
            "flags"         : Flags
            "size"          : Data size
            "mime-type"     : Evaluated content type
        }


exploits
--------

.. code-block:: sh

        {
            'url'         : URL
            'module'      : Module/ActiveX Control, etc. that gets exploited
            'description' : Description of the exploit
            'cve'         : CVE number (if available)
            'data'        : Additional information
        }

classifiers
-----------

.. code-block:: sh

        {
            'classifier'  : Classifier (possible values: html, js, url, sample)
            'url'         : URL
            'rule'        : Rule name
            'tags'        : Rule tags
        }

images
------

.. code-block:: sh

        {
            'url'         : URL
            'classifier'  : Classifier (possible values: OCR)
            'result'      : Analysis result
        }


screenshots
-----------

.. code-block:: sh

        {
            'url'         : URL
            'screenshot'  : Base-64 encoded screenshot
        }


awis
----

.. code-block:: sh

        {
            'awis'       : AWIS reports
        }


File logging mode
=================

The File logging mode allows to store both the analysis results and each resource
downloaded during the analysis in flat files. The File logging mode was enabled by default 
before Thug 0.5.6. If you are using Thug 0.5.7 (or later) you have to explicitely enable 
it through the option *-F* (or *--file-logging*). Please consider that all the information 
stored in flat files are stored in the MongoDB instance (if available). This option could 
be convenient in some situations but if you plan to analyze a huge number of URLs per day 
probably thinking about storing results and resources in a database is better than spread 
such data on your hard drive. 

If you enable the File logging mode the directory which contains the logs for the session
will appear as shown below

.. code-block:: sh

        ~/thug/src $ cd ../logs/baa880d8d79c3488f2c0557be24cca6b/20120702191511
        ~/thug/logs/baa880d8d79c3488f2c0557be24cca6b/20120702191511 $ ls -lhR
        .:
        total 232K
        -rw-r--r-- 1 buffer buffer 1008 Jul  2 19:15 502da89357ca5d7c85dc7a67f8977b21
        -rw-r--r-- 1 buffer buffer  81K Jul  2 19:15 analysis.xml
        drwxr-xr-x 6 buffer buffer  176 Jul  2 19:15 application
        -rwxr-xr-x 1 buffer buffer  89K Jul  2 19:15 d328b5a123bce1c0d20d763ad745303a
        -rw-r--r-- 1 buffer buffer  51K Jul  2 19:15 Ryp.jar
        drwxr-xr-x 3 buffer buffer   72 Jul  2 19:15 text

        ./application:
        total 0
        drwxr-xr-x 2 buffer buffer 96 Jul  2 19:15 java-archive
        drwxr-xr-x 2 buffer buffer 96 Jul  2 19:15 pdf
        drwxr-xr-x 2 buffer buffer 96 Jul  2 19:15 x-msdownload
        drwxr-xr-x 2 buffer buffer 96 Jul  2 19:15 x-shockwave-flash

        ./application/java-archive:
        total 52K
        -rw-r--r-- 1 buffer buffer 51K Jul  2 19:15 e3639fde6ddf7fd0182fff9757143ff2

        ./application/pdf:
        total 16K
        -rw-r--r-- 1 buffer buffer 15K Jul  2 19:15 3660fe0e4acd23ac13f3d043eebd2bbc

        ./application/x-msdownload:
        total 92K
        -rw-r--r-- 1 buffer buffer 89K Jul  2 19:15 d328b5a123bce1c0d20d763ad745303a

        ./application/x-shockwave-flash:
        total 4.0K
        -rw-r--r-- 1 buffer buffer 1008 Jul  2 19:15 502da89357ca5d7c85dc7a67f8977b21

        ./text:
        total 0
        drwxr-xr-x 2 buffer buffer 144 Jul  2 19:15 html

        ./text/html:
        total 72K
        -rw-r--r-- 1 buffer buffer 68K Jul  2 19:15 95ee609e6e3b69c2d9e68f34ff4a4335
        -rw-r--r-- 1 buffer buffer 878 Jul  2 19:15 d26b9b1a1f667004945d1d000cf4f19e
 

In this example the MAEC 1.1 logging mode is enabled and the file *analysis.xml* contains the
URL analysis results saved in MAEC 1.1 format (MAEC 1.1 logging is no longer supported). Please 
notice that all the resources downloaded during the URL analysis are saved in the log directory
based on their Content-Type for convenience. Moreover if MongoDB is installed the information
you can see in this directory are saved in the database instance as well.
