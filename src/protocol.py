"""
Protocol definition for DiFUSE
"""
import json
import socket
from enum import IntEnum, auto
from construct import Struct, Int32ub, Enum, ConstructError, StreamError
import logging
from hashing import Hashing
import hashing
import errno

BOOTSTRAP_PORT = 10921
PORT = 10920


class ProtocolError(Exception):
    """
    Exception class for raising exceptions caused by communication
    errors
    """
    pass


class Verbs(IntEnum):
    """
    Enumerated type to represent the protocol verbs
    """
    ERROR = 0
    OK = auto()
    JOIN = auto()
    EXIT = auto()
    LOOKUP_REQ = auto()
    LOOKUP_RES = auto()
    STAT_REQ = auto()
    STAT_RES = auto()
    READ_REQ = auto()
    READ_RES = auto()
    WRITE_REQ = auto()
    WRITE_RES = auto()
    RENAME_REQ = auto()
    RENAME_RES = auto()
    TRUNC_REQ = auto()
    TRUNC_RES = auto()
    UNLINK_REQ = auto()
    UNLINK_RES = auto()
    READDIR_REQ = auto()
    READDIR_RES = auto()
    XFER = auto()
    IP_TABLE = auto()
    NEW_NODE = auto()
    LEFT_NODE = auto()
    CREATE = auto()


class Status(IntEnum):
    """
    Enumerated type to represent the 'status' protocol packet field
    """
    OK = 0
    ERROR = 1
    ENOENT = errno.ENOENT
    EACCES = errno.EACCES
    EEXIST = errno.EEXIST


def lookup(_bootstrap_ip, path):
    """
    Consistent hashing routine for Lookup
    :param _bootstrap_ip: Unused, keeps interface intact.
    :param path: path/filename to lookup
    :return: IP of the node that contains the path
    """
    file_hash = Hashing.difuse_hash(path)
    succ = hashing.HASHING_OBJ.succ(file_hash)
    return hashing.HASHING_OBJ.ip_table[succ]


def construct_packet(verb, status, payload):
    """
    Constructs a protocol packet given the verb and payload

    Args:
        verb: protocol.Verbs for the packet
        status: protocol.Status code
        payload: dctionary to dump to json

    Returns:
        a bytestring of the packet
    """
    if not isinstance(verb, Verbs):
        raise AttributeError('verb arg must be protocol.Verbs')
    if not isinstance(payload, dict):
        raise AttributeError('payload arg must be dictionary')
    if not isinstance(status, Status):
        raise AttributeError('status arg must be protocol.Status')
    payload_s = json.dumps(payload).encode('ascii')
    logging.debug(f'payload {payload_s}')
    packet = {
        'verb': verb,
        'status': status,
        'payload_size': len(payload_s),
    }
    return HEADER.build(packet) + payload_s


def broadcast_no_recv(verb, payload):
    """
    Broadcasts a Verb with payload to all nodes in the cluster without receiving an ack via recv.
    :param: verb: Verb to broadcast, typically LEFT_NODE or NEW_NODE
    :param: payload: payload to bcast
    :return: None
    """
    for node_ip in Hashing.ip_table.values():
        try:
            node_conn = socket.socket()
            node_conn.connect((node_ip, PORT))
            node_pkt = construct_packet(verb,
                                        Status.OK,
                                        payload)
            node_conn.send(node_pkt)
            node_conn.close()
        except IOError:
            pass


def sock_send_recv(addr, packet, port=PORT):
    """
    Connects to an address on given port, send the packet, receive the response and return that.
    Closes the connection even if an exception is raised.
    :param addr: Address to connect to
    :param packet: packet to send, as returned from construct_packet
    :param port: Port to connect to, default protocol.PORT
    :raises: Protocol Error on and Construct Errors
    :return: Tuple of parsed response header and JSON loaded payload
    """
    conn = socket.socket()
    conn.connect((addr, port))
    try:
        conn.send(packet)
        res = conn.recv(HEADER.sizeof())
        res = HEADER.parse(res)
        payload = conn.recv(res.payload_size)
        payload = json.loads(payload)
        return res, payload
    except (ConstructError, StreamError) as ex:
        raise ProtocolError from ex
    except:
        raise
    finally:
        conn.close()


HEADER = Struct(
    "verb" / Enum(Int32ub, Verbs),
    "status" / Enum(Int32ub, Status),
    "payload_size" / Int32ub,
)
