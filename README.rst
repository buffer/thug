Thug
====

|version badge| |travis badge| |landscape badge| |codefactor badge| |codecov badge|

The number of client-side attacks has grown significantly in the past few years
shifting focus on poorly protected vulnerable clients. Just as the most known
honeypot technologies enable research into server-side attacks, honeyclients
allow the study of client-side attacks.

A complement to honeypots, a honeyclient is a tool designed to mimic the behavior
of a user-driven network client application, such as a web browser, and be
exploited by an attacker's content.

Thug is a Python low-interaction honeyclient aimed at mimicing the behavior of a
web browser in order to detect and emulate malicious contents.


Documentation
-------------

|docs badge|

Documentation about Thug installation and usage can be found at http://thug-honeyclient.readthedocs.io/.


Contributions
-------------

|donate badge|

Thug is open source and we welcome contributions in all forms!

Thug is free to use for any purpose (even commercial ones). If you use and appreciate Thug, please consider
supporting the project with a donation using Paypal.

Development Setup
-----------------

To setup a development environment, follow the steps:

.. code-block:: bash

    git clone https://github.com/buffer/thug.git
    cd thug
    ./dev/dev.sh


The *dev* script will create a `virtualenv`_ environment in a directory called "venv"
and install all the mandatory and optional dependencies into it. Thug is installed as
a permanent package and the package needs to be installed again executing ``pip install .``
in order to compile all the changes.

If you want to install Thug as an "editable", please replace line 11 in `dev.sh` by the
following line and re-run ``dev.sh``

    pip2 install -e .

Installing Thug as an "editable" allows changes to the source in the repository to be reflected
in the virtualenv.

Make sure that you successfully installed Thug by running the following commands:

.. code-block:: bash

    . venv/bin/activate
    thug --version


Testing
-------

To run the full test suite using tox_, run the command:

.. code-block:: bash

    tox

Since tox builds and installs dependencies from scratch, using `pytest`_ for faster testing is recommended:

.. code-block:: bash

    pytest --cov thug


Support
-------

Thanks to |JetBrains|_ for free |PyCharm|_ licenses!


License information
-------------------

Copyright (C) 2011-2019 Angelo Dell'Aera <angelo.dellaera@honeynet.org>

License: GNU General Public License, version 2


.. |version badge| image:: https://img.shields.io/pypi/v/thug.svg
   :target: https://pypi.python.org/pypi/thug/
.. |travis badge| image:: https://img.shields.io/travis/buffer/thug/master.svg
   :target: https://travis-ci.org/buffer/thug
.. |landscape badge| image:: https://landscape.io/github/buffer/thug/master/landscape.png
   :target: https://landscape.io/github/buffer/thug/master
   :alt: Code Health
.. |codefactor badge| image:: https://www.codefactor.io/repository/github/buffer/thug/badge
   :target: https://www.codefactor.io/repository/github/buffer/thug
.. |codecov badge| image:: https://codecov.io/gh/buffer/thug/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/buffer/thug
.. |docs badge| image:: https://readthedocs.org/projects/thug-honeyclient/badge/?version=latest
   :target: http://thug-honeyclient.readthedocs.io/en/latest/?badge=latest
.. |donate badge| image:: https://img.shields.io/badge/Donate-PayPal-green.svg
   :target: https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=XTDF8AHJ28CXY
.. |JetBrains| image:: /docs/images/pycharm/jetbrains.svg
.. _JetBrains: https://www.jetbrains.com/?from=thug
.. |PyCharm| image:: /docs/images/pycharm/pycharm.png
.. _PyCharm: https://www.jetbrains.com/?from=thug
.. _virtualenv: https://virtualenv.pypa.io/
.. _tox: https://tox.readthedocs.io/
.. _`pytest`: http://pytest.org/
