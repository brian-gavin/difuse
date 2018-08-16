"""
Implements consistent hashing related functions and data structures, namely functions for the consistent hashing
'unit circle', named HASH_UNIT, which is the sorted list of ID hashes
"""

import bisect
import hashlib
from threading import Lock


class Hashing:
    """
    "static" Class to hold consistent hashing data structures and methods
    """
    lock: Lock
    hash_unit: list
    ip_table: dict
    id_hash: bytes

    @classmethod
    def __init__(cls, hash_unit, ip_table, id_hash):
        """
        Initialize the hashing module
        :param hash_unit: initial hashing unit circle: sorted list of node ID hashes
        :param ip_table: dictionary mapping Node IDs to IP addresses
        :param id_hash: ID of the node
        :return:
        """
        cls.hash_unit = hash_unit
        cls.ip_table = ip_table
        cls.id_hash = id_hash
        cls.lock = Lock()

    @staticmethod
    def difuse_hash(b):
        """
        Hashes a string according to the used hash algorithm
        :param b: bytes to be hashed. If this is type str, it will be converted to bytes
        :return: the hash of the filename
        """
        hasher = hashlib.md5()
        if isinstance(b, str):
            b = b.encode('ascii')
        if not isinstance(b, bytes):
            raise TypeError('bytes to hash must be type string or bytes')
        hasher.update(b)
        return hasher.digest()

    @classmethod
    def add_node(cls, ip):
        """
        Adds a node to the hash space, adding it to the sorted list of hashes
        :param ip: ip of the node
        :return: None
        """
        id_hash = cls.difuse_hash(ip)
        with cls.lock:
            index = bisect.bisect_left(cls.hash_unit, id_hash)
            if id_hash not in cls.hash_unit:
                cls.hash_unit.insert(index, id_hash)
            cls.ip_table[id_hash] = ip

    @classmethod
    def remove_node(cls, id_hash):
        """
        Removes a node from the hash space and IP Table mapping
        :param id_hash: ID Hash for the node
        :return: None
        """
        with cls.lock:
            cls.hash_unit.remove(id_hash)
            del cls.ip_table[id_hash]

    @classmethod
    def succ(cls, hashed_val):
        """
        Computes the successor for the given hashed value
        :param hashed_val: the hashed value to compute the successor
        :return: Value of the successor
        """
        return cls.hash_unit[bisect.bisect_right(cls.hash_unit, hashed_val) % len(cls.hash_unit)]

    @classmethod
    def serializable_ip_table(cls):
        """
        Returns a serializable form of the IP Table (bytes type is not serializable, so it needs a transform)

        the serializable hash table maps the table backwards, it has to transform the bytes key to a list, and list is
        not a valid type for a dictionary key.
        :return: Serializable transform of the IP Table
        """
        return {ip: list(id_hash) for id_hash, ip in cls.ip_table.items()}

    @staticmethod
    def deserializable_ip_table(serializable_ip_table):
        """
        Transforms the serializable ip table (returned from serializable_ip_table method) to the regular form
        :return: IP_table
        """
        return {bytes(id_list): ip for ip, id_list in serializable_ip_table.items()}

# Hashing 'singleton'
HASHING_OBJ: Hashing
