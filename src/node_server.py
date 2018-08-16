"""
DiFUSE Node
"""

import json
import os
from os.path import join
import socket
import logging
from construct import ConstructError
import protocol
from node_const import LOCAL_ROOT
import hashing
from hashing import Hashing
from node_const import relocate_files

HOST = '0.0.0.0'


class DifuseServer:
    """
    Server for the node. Accepts requests and issues syscalls on the fuse
    mount.
    """

    def __init__(self, bootstrap_ip, fuse_mount):
        """
        init the node server, join the cluster, construct the listening socket
        """
        self.fuse_mount = fuse_mount
        self.bootstrap_ip = bootstrap_ip

        # establish server socket
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((HOST, protocol.PORT))
        self.sock.listen(5)

        # Send JOIN to the bootstrap and initialize the Hashing data structures
        req_pkt = protocol.construct_packet(protocol.Verbs.JOIN,
                                            protocol.Status.OK,
                                            {})
        try:
            # send JOIN and receive IP_TABLE
            header, payload = protocol.sock_send_recv(bootstrap_ip, req_pkt, protocol.BOOTSTRAP_PORT)
            logging.debug(f'received {header}')
            if header.status != protocol.Status.OK.name:
                raise IOError('Did not received status: ok')

            # init the hashing object using the Bootstrap's data
            ip_table = Hashing.deserializable_ip_table(payload['ip_table'])
            hash_unit = sorted(ip_table.keys())
            id_hash = Hashing.difuse_hash(payload['ip'])
            hashing.HASHING_OBJ = Hashing(hash_unit, ip_table, id_hash)
            logging.info(f'ID: {id_hash}')
            # if files need to be relocated, relocate them
            relocate_files()
        except IOError as ex:
            logging.exception(ex)

    def __del__(self):
        if hasattr(self, 'sock'):
            self.sock.close()

    @staticmethod
    def handle_stat_req(conn, payload):
        """
        Handles a stat_req

        :conn: connection to requesting node
        :payload: contains the filename to stat
        """
        res_pkt = b''
        try:
            stat = os.stat(join(LOCAL_ROOT, payload['filename']))
        except FileNotFoundError as ex:
            logging.exception(ex)
            res_pkt = protocol.construct_packet(protocol.Verbs.STAT_RES,
                                                protocol.Status.ENOENT,
                                                {})
        except PermissionError as ex:
            logging.exception(ex)
            res_pkt = protocol.construct_packet(protocol.Verbs.STAT_RES,
                                                protocol.Status.EACCES,
                                                {})
        except Exception:
            res_pkt = protocol.construct_packet(protocol.Verbs.STAT_RES,
                                                protocol.Status.ERROR,
                                                {})
        else:
            res_payload = {'stat': stat}
            res_pkt = protocol.construct_packet(protocol.Verbs.STAT_RES,
                                                protocol.Status.OK,
                                                res_payload)
        finally:
            conn.send(res_pkt)

    @staticmethod
    def handle_read_req(conn, payload):
        """
        Handles a read_req
        """
        res_pkt = b''
        try:
            path = join(LOCAL_ROOT, payload['filename'])
            offset = payload['offset']
            cnt = payload['cnt']
            f = open(path, 'rb')
        except FileNotFoundError:
            res_pkt = protocol.construct_packet(protocol.Verbs.READ_RES,
                                                protocol.Status.ENOENT,
                                                {})
        except Exception as ex:
            logging.exception(ex)
            res_pkt = protocol.construct_packet(protocol.Verbs.READ_RES,
                                                protocol.Status.ENOENT,
                                                {})
        else:
            f.seek(offset)
            buf = f.read(cnt)
            res_pkt = protocol.construct_packet(protocol.Verbs.READ_RES,
                                                protocol.Status.ERROR,
                                                {})
            read_res = list(buf)
            res_payload = {
                'bytes': read_res,
                'cnt': len(read_res)
            }
            res_pkt = protocol.construct_packet(protocol.Verbs.READ_RES,
                                                protocol.Status.OK,
                                                res_payload)
            f.close()
        finally:
            conn.send(res_pkt)

    @staticmethod
    def handle_write_req(conn, payload):
        """
        Handle write request
        """
        res_pkt = b''
        try:
            path = join(LOCAL_ROOT, payload['filename'])
            offset = payload['offset']
            data = bytes(payload['bytes'])
            fd = os.open(path, os.O_WRONLY)
        except FileNotFoundError:
            res_pkt = protocol.construct_packet(protocol.Verbs.WRITE_RES,
                                                protocol.Status.ENOENT,
                                                {})
        except Exception as ex:
            logging.exception(ex)
            res_pkt = protocol.construct_packet(protocol.Verbs.WRITE_RES,
                                                protocol.Status.ERROR,
                                                {})
        else:
            os.lseek(fd, offset, os.SEEK_SET)
            writen = os.write(fd, data)
            res_payload = {
                'cnt': writen
            }
            res_pkt = protocol.construct_packet(protocol.Verbs.WRITE_RES,
                                                protocol.Status.OK,
                                                res_payload)
            os.close(fd)
        finally:
            conn.send(res_pkt)

    @staticmethod
    def handle_trunc_req(conn, payload):
        """
        handles trunc requet
        """
        res_pkt = b''
        try:
            path = join(LOCAL_ROOT, payload['filename'])
            size = payload['len']
            os.truncate(path, size)
        except Exception:
            res_pkt = protocol.construct_packet(protocol.Verbs.TRUNC_RES,
                                                protocol.Status.ERROR,
                                                {})
        else:
            res_pkt = protocol.construct_packet(protocol.Verbs.TRUNC_RES,
                                                protocol.Status.OK,
                                                {})
        finally:
            conn.send(res_pkt)

    def handle_unlink_req(self, conn, payload):
        """
        Handles unlink request, removes file and responds to the conn
        """
        res_pkt = b''
        try:
            os.unlink(join(LOCAL_ROOT, payload['filename']))
        except FileNotFoundError as ex:
            logging.exception(ex)
            res_pkt = protocol.construct_packet(protocol.Verbs.UNLINK_RES,
                                                protocol.Status.ENOENT,
                                                {})
        except PermissionError as ex:
            logging.exception(ex)
            res_pkt = protocol.construct_packet(protocol.Verbs.UNLINK_RES,
                                                protocol.Status.EACCES,
                                                {})
        except Exception as ex:
            logging.exception(ex)
            res_pkt = protocol.construct_packet(protocol.Verbs.UNLINK_RES,
                                                protocol.Status.ERROR,
                                                {})
        else:
            res_pkt = protocol.construct_packet(protocol.Verbs.UNLINK_RES,
                                                protocol.Status.OK,
                                                {})
        finally:
            conn.send(res_pkt)

    def handle_xfer_res(self, conn, payload):
        """
        Handles the XFER_RES, copying all the files in the payload to the local root
        :param conn: connection
        :param payload: payload: list of files
        :return: None
        """
        files_list = payload['files']
        for file_dict in files_list:
            try:
                with open(join(LOCAL_ROOT, file_dict['filename']), 'wb') as f:
                    f.write(bytes(file_dict['bytes']))
            except Exception as ex:
                logging.exception(ex)
        pkt = protocol.construct_packet(protocol.Verbs.OK, protocol.Status.OK, {})
        conn.send(pkt)

    @staticmethod
    def handle_new_node(_conn, payload):
        """
        Handles NEW_NODE, add the new node id to the hashing data structures
        :param conn: open connection
        :param payload: payload: contains the IP of the new node
        :return: None
        """
        try:
            hashing.HASHING_OBJ.add_node(payload['ip'])
        except KeyError as ex:
            logging.exception(ex)

        relocate_files()

    @staticmethod
    def handle_create(conn, payload):
        """
        Handles CREATE: creates a file in the local filesystem
        :param: conn: open connection
        :param: payload: contains the filename of the file to send
        :return: None
        """
        try:
            name = payload['filename']
        except KeyError as ex:
            logging.exception(ex)
            return
        pkt = b''
        try:
            open(join(LOCAL_ROOT, name), 'x').close()
        except FileExistsError:
            pkt = protocol.construct_packet(protocol.Verbs.ERROR,
                                            protocol.Status.EEXIST,
                                            {})
        except PermissionError:
            pkt = protocol.construct_packet(protocol.Verbs.ERROR,
                                            protocol.Status.EACCES,
                                            {})
        except Exception as ex:
            pkt = protocol.construct_packet(protocol.Verbs.ERROR,
                                            protocol.Status.ERROR,
                                            {})
            logging.exception(ex)
        else:
            pkt = protocol.construct_packet(protocol.Verbs.OK,
                                            protocol.Status.OK,
                                            {})
        finally:
            conn.send(pkt)

    @staticmethod
    def handle_left_node(_conn, payload):
        """
        handles a LEFT_NODE, removing a node's mapping from the IP Table and hash unit
        :param conn: open connection
        :param payload: payload: will contain the IP of the node that left
        :return: None
        """
        try:
            hashing.HASHING_OBJ.remove_node(Hashing.difuse_hash(payload['ip']))
        except KeyError as ex:
            logging.exception(ex)


    @staticmethod
    def handle_readdir(conn, _payload):
        '''
        handles READDIR, responding to the connection with a list of the files on the local root
        :param conn: open connection
        :param payload: payload, empty
        :return: None
        '''
        pkt = b''
        try:
            entries = os.listdir(LOCAL_ROOT)
        except Exception:
            pkt = protocol.construct_packet(protocol.Verbs.READDIR_RES,
                                            protocol.Status.ERROR,
                                            {})
        else:
            pkt = protocol.construct_packet(protocol.Verbs.READDIR_RES,
                                            protocol.Status.OK,
                                            {'entries': entries})
        finally:
            conn.send(pkt)

    def serve(self):
        """
        Serves requests from other nodes
        """
        while True:
            conn, addr = self.sock.accept()
            try:
                req = conn.recv(protocol.HEADER.sizeof())
                req = protocol.HEADER.parse(req)
                payload = conn.recv(req.payload_size)
                logging.info(f'received: {req}\n{payload}')
                # STAT_REQ
                if req.verb == protocol.Verbs.STAT_REQ.name:
                    self.handle_stat_req(conn, json.loads(payload))
                # READ_REQ
                elif req.verb == protocol.Verbs.READ_REQ.name:
                    self.handle_read_req(conn, json.loads(payload))
                # WRITE_REQ
                elif req.verb == protocol.Verbs.WRITE_REQ.name:
                    self.handle_write_req(conn, json.loads(payload))
                # TRUNC
                elif req.verb == protocol.Verbs.TRUNC_REQ.name:
                    self.handle_trunc_req(conn, json.loads(payload))
                # UNLINK
                elif req.verb == protocol.Verbs.UNLINK_REQ.name:
                    self.handle_unlink_req(conn, json.loads(payload))
                # XFER
                elif req.verb == protocol.Verbs.XFER.name:
                    self.handle_xfer_res(conn, json.loads(payload))
                # NEW_NODE
                elif req.verb == protocol.Verbs.NEW_NODE.name:
                    self.handle_new_node(conn, json.loads(payload))
                # CREATE
                elif req.verb == protocol.Verbs.CREATE.name:
                    self.handle_create(conn, json.loads(payload))
                # LEFT_NODE
                elif req.verb == protocol.Verbs.LEFT_NODE.name:
                    self.handle_left_node(conn, json.loads(payload))
                # READDIR_REQ
                elif req.verb == protocol.Verbs.READDIR_REQ.name:
                    self.handle_readdir(conn, json.loads(payload))
                # Unsupported/Unexpected request
                else:
                    err_pkt = protocol.construct_packet(protocol.Verbs.ERROR,
                                                        protocol.Status.ERROR,
                                                        {'msg': 'unsupported operation'})
                    conn.send(err_pkt)
            except ConstructError:
                logging.error(f'bad packet from {addr}')
            finally:
                conn.close()
