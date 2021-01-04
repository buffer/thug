Thug
====

|version badge| |github badge| |lgtm badge| |codefactor badge| |codecov badge| |bandit badge|

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


Testing
-------

To run the full test suite using tox_, run the command:

.. code-block:: bash

    tox

Since tox builds and installs dependencies from scratch, using `pytest`_ for faster testing is recommended:

.. code-block:: bash

    pytest --cov thug


License information
-------------------

Copyright (C) 2011-2021 Angelo Dell'Aera <angelo.dellaera@honeynet.org>

License: GNU General Public License, version 2


.. |version badge| image:: https://img.shields.io/pypi/v/thug.svg
   :target: https://pypi.python.org/pypi/thug/
.. |github badge| image:: https://github.com/buffer/thug/workflows/Build/badge.svg
   :target: https://github.com/buffer/thug
.. |lgtm badge| image:: https://img.shields.io/lgtm/grade/python/g/buffer/thug.svg?logo=lgtm&logoWidth=18
   :target: https://lgtm.com/projects/g/buffer/thug
.. |codefactor badge| image:: https://www.codefactor.io/repository/github/buffer/thug/badge
   :target: https://www.codefactor.io/repository/github/buffer/thug
.. |codecov badge| image:: https://codecov.io/gh/buffer/thug/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/buffer/thug
.. |bandit badge| image:: https://img.shields.io/badge/security-bandit-yellow.svg
   :target: https://github.com/PyCQA/bandit
.. |docs badge| image:: https://readthedocs.org/projects/thug-honeyclient/badge/?version=latest
   :target: http://thug-honeyclient.readthedocs.io/en/latest/?badge=latest
.. |donate badge| image:: https://img.shields.io/badge/Donate-PayPal-green.svg
   :target: https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=XTDF8AHJ28CXY
.. _virtualenv: https://virtualenv.pypa.io/
.. _tox: https://tox.readthedocs.io/
.. _`pytest`: http://pytest.org/
