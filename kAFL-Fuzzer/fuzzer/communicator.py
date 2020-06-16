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
import select
from multiprocessing.connection import Listener, Client

MSG_HELLO = 0
MSG_NEW_TASK = 1
MSG_QUEUE_STATUS = 2
MSG_TASK_RESULTS = 3
MSG_NEW_INPUT = 4


class ServerConnection:

    def __init__(self, config):

        Listener.fileno = lambda self: self._listener._socket.fileno()

        self.address = config.argument_values["work_dir"] + "/slave_socket"
        self.listener = Listener(self.address, 'AF_UNIX')
        self.clients = [self.listener]

    def wait(self):
        results = []
        print
        "selecting"
        r, w, e = select.select(self.clients, (), ())
        for sock_ready in r:
            if sock_ready == self.listener:
                print
                "accepting new client"
                c = self.listener.accept()
                self.clients.append(c)
            else:
                try:
                    msg = sock_ready.recv_bytes()
                    msg = msgpack.unpackb(msg)
                    results.append((sock_ready, msg))
                    # print "received {}".format(msg)
                except EOFError:
                    print
                    "closing"
                    sock_ready.close()
                    self.clients.remove(sock_ready)
        return results

    def send_task(self, client, task_data):
        client.send_bytes(msgpack.packb({"type": MSG_NEW_TASK, "task": task_data}))

    def queue_status(self, client):
        pass


class ClientConnection:
    def __init__(self, id, config):
        self.id = id
        self.address = config.argument_values["work_dir"] + "/slave_socket"
        self.sock = self.connect()
        self.send_hello()

    def connect(self):
        sock = Client(self.address, 'AF_UNIX')
        return sock

    def recv(self):
        data = self.sock.recv_bytes()
        return msgpack.unpackb(data)

    def send_hello(self):
        print
        "sending CLIENT_HELLO"
        self.sock.send_bytes(msgpack.packb({"type": MSG_HELLO, "client_id": self.id}))

    def send_new_input(self, data, bitmap, info):
        self.sock.send_bytes(
            msgpack.packb({"type": MSG_NEW_INPUT, "input": {"payload": data, "bitmap": bitmap, "info": info}}))

    def send_task_performed(self, node_id, results, new_payload):
        self.sock.send_bytes(msgpack.packb(
            {"type": MSG_TASK_RESULTS, "node_id": node_id, "results": results, "new_payload": new_payload}))

    def send_slave_status(self):
        pass

    def send_terminated(self):
        pass
