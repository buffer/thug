MongoDB Logging module
======================

MongoDB collection schema is documented here.


Collection urls
^^^^^^^^^^^^^^^

.. code-block:: sh

        { 
            "url" : URL
        }

Collection analyses
^^^^^^^^^^^^^^^^^^^

.. code-block:: sh


        { 
            "url"         : Initial URL url_id
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

Collection connections 
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: sh

        { 
            "analysis_id"   : Analysis ID
            "chain_id"      : Chain ID 
            "source"        : Source URL url_id
            "destination"   : Destination URL url_id
            "method"        : Method
            "flags"         : Flags
        }


Collection locations 
^^^^^^^^^^^^^^^^^^^^

.. code-block:: sh


        { 
            "analysis_id"   : Analysis ID
            "url_id"        : URL url_id
            "content_id"    : Content ID (content stored in the GridFS fs)
            "content-type"  : Content Type
            "md5"           : MD5 checksum
            "sha256"        : SHA-256 checksum
            "flags"         : Flags
            "size"          : Data size
            "mime-type"     : Evaluated content type
        }

Collection samples
^^^^^^^^^^^^^^^^^^

.. code-block:: sh

        { 
            "analysis_id"   : Analysis ID
            "url_id"        : URL url_id
            "sample_id"     : Sample ID (sample stored in the GridFS fs)
            "type"          : Sample type
            "md5"           : MD5 checksum
            "sha1"          : SHA-1 checksum
            "imphash"       : Imphash (if type is PE)
            "data"          : Sample
        }
