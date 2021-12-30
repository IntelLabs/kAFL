# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Abstractions for kAFL Master/Slave communicaton.
"""

import msgpack
import select
from multiprocessing.connection import Listener, Client

from common.log import logger

MSG_READY = 0
MSG_IMPORT = 1
MSG_RUN_NODE = 2
MSG_NODE_DONE = 3
MSG_NODE_ABORT = 6
MSG_NEW_INPUT = 4
MSG_BUSY = 5


class ServerConnection:
    def __init__(self, config):
        Listener.fileno = lambda self: self._listener._socket.fileno()
        self.address = config.argument_values["work_dir"] + "/slave_socket"
        self.listener = Listener(self.address, 'AF_UNIX', backlog=1000)
        self.clients = [self.listener]
        self.clients_seen = 0

    def wait(self, timeout=None):
        results = []
        r, w, e = select.select(self.clients, (), (), timeout)
        for sock_ready in r:
            if sock_ready == self.listener:
                c = self.listener.accept()
                self.clients.append(c)
                self.clients_seen += 1
            else:
                try:
                    msg = sock_ready.recv_bytes()
                    msg = msgpack.unpackb(msg, strict_map_key=False)
                    results.append((sock_ready, msg))
                except (EOFError, IOError):
                    sock_ready.close()
                    self.clients.remove(sock_ready)
                    logger.info("Slave disconnected (remaining %d/%d)." % (len(self.clients)-1, self.clients_seen))
                    if len(self.clients) == 1:
                        raise SystemExit("All slaves have died.")
        return results

    def send_import(self, client, task_data):
        client.send_bytes(msgpack.packb({"type": MSG_IMPORT, "task": task_data}))

    def send_node(self, client, task_data):
        client.send_bytes(msgpack.packb({"type": MSG_RUN_NODE, "task": task_data}))

    def send_busy(self, client):
        client.send_bytes(msgpack.packb({"type": MSG_BUSY}))


class ClientConnection:
    def __init__(self, id, config):
        self.id = id
        self.address = config.argument_values["work_dir"] + "/slave_socket"
        self.sock = self.connect()
        self.send_ready()

    def connect(self):
        sock = Client(self.address, 'AF_UNIX')
        return sock

    def recv(self):
        data = self.sock.recv_bytes()
        return msgpack.unpackb(data, strict_map_key=False)

    def send_ready(self):
        self.sock.send_bytes(msgpack.packb({"type": MSG_READY, "client_id": self.id}))

    def send_new_input(self, data, bitmap, info):
        self.sock.send_bytes(
            msgpack.packb({"type": MSG_NEW_INPUT, "input": {"payload": data, "bitmap": bitmap, "info": info}}))

    def send_node_done(self, node_id, results, new_payload):
        self.sock.send_bytes(msgpack.packb(
            {"type": MSG_NODE_DONE, "node_id": node_id, "results": results, "new_payload": new_payload}))

    def send_node_abort(self, node_id, results):
        self.sock.send_bytes(msgpack.packb(
            {"type": MSG_NODE_ABORT, "node_id": node_id, "results": results}))
