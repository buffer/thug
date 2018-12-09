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

Thug is open source and we welcome contributions in all forms. If you would like to work on a large contribution please
discuss the same with the maintainers of the project.

Thug is free to use for any purpose (even commercial ones). If you use and appreciate Thug, consider supporting the project with a donation
using Paypal (details at https://buffer.github.com/thug/).

Development Setup
-----------------

To setup thug's development environment, follow the steps:

.. code-block:: bash

    git clone https://github.com/buffer/thug.git
    cd thug
    ./dev/dev.sh


The *dev* script will create a `virtualenv`_ environment in a directory called "venv"
and install all mandatory and optional dependencies into it. Thug is installed as
a permanent package and to compile all the changes, the package needs to be installed again by ``pip install .``

If you want to install thug as an "editable", please replace the
line11 in `dev.sh` by the following line and re-run ``dev.sh``

    pip2 install -e .

Installing thug as an "editable" will allow any changes to the source in the repository to be reflected
live in the virtualenv.

Make sure that you successfully installed thug by running these commands:

.. code-block:: bash

    . venv/bin/activate
    thug --version


Testing
-------

To run the full test suite using tox_, type this command:

.. code-block:: bash

    tox

Since tox builds and installs the dependencies from scratch, we recommend using `pytest`_ for faster testing:

.. code-block:: bash

    pytest --cov thug

To test individual test files or folders:

.. code-block:: bash

    cd tests/Java
    pytest --cov thug.Java.lang test_lang.py


Support
-------

Thanks to |JetBrains|_ for free |PyCharm|_ licenses!


License information
-------------------

Copyright (C) 2011-2018 Angelo Dell'Aera <angelo.dellaera@honeynet.org>

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
.. |JetBrains| image:: /docs/images/pycharm/jetbrains.svg
.. _JetBrains: https://www.jetbrains.com/?from=thug
.. |PyCharm| image:: /docs/images/pycharm/pycharm.png
.. _PyCharm: https://www.jetbrains.com/?from=thug
.. _virtualenv: https://virtualenv.pypa.io/
.. _tox: https://tox.readthedocs.io/
.. _`pytest`: http://pytest.org/
