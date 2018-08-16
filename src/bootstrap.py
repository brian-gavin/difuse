#! /usr/bin/env python3
"""
Bootstrap node for DiFUSE file system
"""

import socket
import threading
import argparse
import sys
from queue import Queue
import json
from construct import ConstructError
import protocol
import logging
import signal
import hashing
from hashing import Hashing

HOST = '0.0.0.0'


def sigint_handler(_a, _b):
    exit(0)


class Bootstrap:
    """
    Bootstrap class
    """

    def __init__(self, thread_cnt):
        """
        Initializes boostrap
        """
        self.queue = Queue()
        self.sock = None
        hashing.HASHING_OBJ  = Hashing([], {}, b'')
        for n in range(thread_cnt):
            logging.info(f'starting thread {n}')
            threading.Thread(target=work_routine, args=[self], name=f'Worker Thread {n}', daemon=True).start()

    def __enter__(self):
        """
        Context maanager protocol, creates the listening socket for the
        bootstrap node
        """
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((HOST, protocol.BOOTSTRAP_PORT))
        self.sock.listen(10)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Context manager protocol, closes the listening socket
        """
        self.sock.close()

    def serve(self):
        """
        Spins and serves requests
        """
        while True:
            logging.debug('spinning')
            accept_pair = self.sock.accept()
            ip = accept_pair[1]
            logging.info(f'incoming connection from {ip}')
            self.queue.put(accept_pair)


def work_routine(bootstrap):
    """
    Routine for worker threads. gets messages from queue and calls handler
    """
    while True:
        conn, addr = bootstrap.queue.get()
        try:
            buf = conn.recv(protocol.HEADER.sizeof())
            req = protocol.HEADER.parse(buf)
            payload = conn.recv(req.payload_size)
            logging.info(f'received: {req}\n{payload}')
            # JOIN
            if req.verb == protocol.Verbs.JOIN.name:
                handle_join(bootstrap, conn, addr, json.loads(payload))
            # EXIT
            elif req.verb == protocol.Verbs.EXIT.name:
                handle_exit(bootstrap, conn, addr, json.loads(payload))
            # Unsupported/invalid request
            else:
                logging.info(f'unsupported operation {req.verb}')
                err_pkt = protocol.construct_packet(protocol.Verbs.ERROR,
                                                    protocol.Status.ERROR,
                                                    {'msg': 'unsupported operation'})
                conn.send(err_pkt)
        except ConstructError as ex:
            logging.error(f'bad packet {req} from connection {addr}: {ex}')
        finally:
            conn.close()


def handle_exit(_bootstrap, conn, addr, _payload):
    """
    Handles EXIT verb.

    Removes the entry from the IP Table and broadcasts LEFT_NODE to all nodes in the cluster
    """
    # remove node
    hashing.HASHING_OBJ.remove_node(Hashing.difuse_hash(addr[0]))

    # send ack
    try:
        res_pkt = protocol.construct_packet(protocol.Verbs.OK,
                                        protocol.Status.OK,
                                        {})
        conn.send(res_pkt)
    except IOError as ex:
        logging.exception(ex)

    # bcast LEFT_NODE
    protocol.broadcast_no_recv(protocol.Verbs.LEFT_NODE, {'ip': addr[0]})

def handle_join(_bootstrap, conn, addr, _payload):
    """
    Handles the JOIN protocol verb
    """
    logging.info(f'JOIN request from {addr}')

    # add new node to IP Table
    hashing.HASHING_OBJ.add_node(addr[0])
    # send NEW_NODE to cluster
    protocol.broadcast_no_recv(protocol.Verbs.NEW_NODE, {'ip': addr[0]})
    # send ip table to joining conn
    ip_table_payload = {
        'ip': addr[0],
        'ip_table': hashing.HASHING_OBJ.serializable_ip_table()
    }
    logging.info(f'IP_TABLE: {hashing.HASHING_OBJ.ip_table}')
    ip_table_pkt = protocol.construct_packet(protocol.Verbs.IP_TABLE,
                                             protocol.Status.OK,
                                             ip_table_payload)
    conn.send(ip_table_pkt)


def main(args):
    """
    Main routine. Init bootstrap and spin
    """
    with Bootstrap(args.threads) as bootstrap:
        bootstrap.serve()


if __name__ == '__main__':
    signal.signal(signal.SIGINT, sigint_handler)
    logging.basicConfig(level=logging.DEBUG)
    parser = argparse.ArgumentParser(description='DiFUSE Bootstrap')
    parser.add_argument('--threads', type=int, required=False, default=1, help='Thread count')
    sys.exit(main(parser.parse_args()))
