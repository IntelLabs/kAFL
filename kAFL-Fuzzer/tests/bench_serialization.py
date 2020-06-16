"""
Copyright (C) 2019  Sergej Schumilo, Cornelius Aschermann, Tim Blazytko

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import msgpack
import umsgpack
import cbor
#import ubjson

import timeit

NUM_ROUNDS = 10000

global messages
messages = [
        {'call_id': 1, 'kwargs': {}, 'args': ['sleep', 0.1]},
        {'call_id': 1, 't': 'r', 'returned': 'd53b2823d35b471282ab5c8b6c2e4685'},
        {'call_id': 2, 'kwargs': {'utc': True}, 'args': ['date', '%d-%m-%Y %H:%M %Z']},
        {'call_id': 2, 't': 'r', 'returned': '77da239342e240a0a3078d50019a20a0'},
        {'call_id': 1, 'data': {'status': 'started', 'task_id': 'd53b2823d35b471282ab5c8b6c2e4685'}, 't': 'm'},
        {'call_id': 2, 'data': {'status': 'started', 'task_id': '77da239342e240a0a3078d50019a20a0'}, 't': 'm'},
        {'call_id': 1, 'data': {'status': 'success', 'task_id': 'd53b2823d35b471282ab5c8b6c2e4685', 'result': None, 'duration': 0.12562298774719238}, 't': 'm'},
        {'call_id': 2, 'data': {'status': 'success', 'task_id': '77da239342e240a0a3078d50019a20a0', 'result': '27-02-2017 11:46 UTC', 'duration': 0.04673957824707031}, 't': 'm'},
        {'call_id': 2, 'data': {'status': 'success', 'task_id': '77da239342e240a0a3078d50019a20a0', 'result': '27-02-2017 11:46 UTC', 'duration': 0.04673957824707031}, 't': 'm',
            'foo': {'call_id': 2, 'data': {'status': 'success', 'task_id': '77da239342e240a0a3078d50019a20a0', 'result': '27-02-2017 11:46 UTC', 'duration': 0.04673957824707031}, 't': 'm'}},
        ]

def msgpack_pack():
    global messages

    sz=0
    for m in messages:
        sz+= len(msgpack.packb(m))
    return sz

def msgpack_unpack():
    global messages

    for m in messages:
        msgpack.unpackb(msgpack.packb(m))


def umsgpack_pack():
    global messages

    sz=0
    for m in messages:
        sz+= len(umsgpack.packb(m))
    return sz

def umsgpack_unpack():
    global messages

    for m in messages:
        umsgpack.unpackb(umsgpack.packb(m))

def cbor_unpack():
    global messages

    sz=0
    for m in messages:
        sz+= len(cbor.dumps(m))
    return sz


def cbor_pack():
    global messages

    for m in messages:
        cbor.loads(cbor.dumps(m))


print(" msgpack pack/unpack: %f" % timeit.timeit(stmt=msgpack_unpack, number=NUM_ROUNDS))
print("umsgpack pack/unpack: %f" % timeit.timeit(stmt=umsgpack_unpack, number=NUM_ROUNDS))
print("    cbor pack/unpack: %f" % timeit.timeit(stmt=cbor_unpack, number=NUM_ROUNDS))
