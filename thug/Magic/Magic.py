#!/usr/bin/env python
#
# Encoding.py
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA  02111-1307  USA

import magic


class Magic(object):
    def __init__(self, data):
        self.data = data

    def get_mime(self):
        try:
            # This works with python-magic >= 0.4.6 from pypi
            mtype = magic.from_buffer(self.data, mime = True)
        except Exception:
            try:
                # Ubuntu workaround
                # This works with python-magic >= 5.22 from Ubuntu (apt)
                ms = magic.open(magic.MAGIC_MIME)
                ms.load()
                mtype = ms.buffer(self.data).split(';')[0]
            except Exception:
                # Filemagic workaround
                # This works with filemagic >= 1.6 from pypi
                with magic.Magic(flags = magic.MAGIC_MIME_TYPE) as m:  # pylint:disable=unexpected-keyword-arg
                    mtype = m.id_buffer(self.data)

        return mtype
