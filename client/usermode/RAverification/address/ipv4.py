# Copyright (C) 2003-2007, 2009-2011 Nominum, Inc.
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NOMINUM DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NOMINUM BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""IPv4 helper functions."""

import struct

import RAverification.address.exception

def inet_ntoa(address):
    if len(address) != 4:
        raise RAverification.address.exception.SyntaxError
    return '%u.%u.%u.%u' % (address[0], address[1],
                            address[2], address[3])

def inet_aton(text):
    parts = text.split('.')
    if len(parts) != 4:
        raise RAverification.address.exception.SyntaxError
    for part in parts:
        if not part.isdigit():
            raise RAverification.address.exception.SyntaxError
        if len(part) > 1 and part[0] == '0':
            # No leading zeros
            raise RAverification.address.exception.SyntaxError
    try:
        bytes = [int(part) for part in parts]
        return struct.pack('BBBB', *bytes)
    except:
        raise RAverification.address.exception.SyntaxError
