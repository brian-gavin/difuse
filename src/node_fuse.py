"""
Node FUSE file system implementation
"""
from node_const import LOCAL_ROOT
import errno
import logging
import os
from os.path import join
from construct import ConstructError, StreamError
from fuse import LoggingMixIn, Operations, FuseOSError
import protocol
from protocol import ProtocolError
import hashing
from socket import socket
import json
from node_const import relocate_files


class Difuse(LoggingMixIn, Operations):
    """
    FUSE implementation class for DiFUSE node file server
    """

    def __init__(self, bootstrap_ip):
        """
        Initializes the FUSE impl
        """
        self.bootstrap_ip = bootstrap_ip
        self.fd = 0

    @staticmethod
    def _stat_dict(stat_obj):
        """
        Translates a stat object to a dictionary for getattr
        """
        attributes = [attr for attr in dir(stat_obj) if attr.startswith('st')]
        d = {attr: stat_obj.__getattribute__(attr) for attr in attributes}
        for key in d.keys():
            if isinstance(d[key], type(None)):
                d[key] = 0
        logging.debug(d)
        return d

    def chmod(self, path, mode):
        """
        Chmod: not implemented
        """
        pass

    def chown(self, path, uid, gid):
        """
        Chown: not implemented
        """
        pass

    def create(self, path, mode, fi=None):
        """

        :param path: filename
        :param mode: mode to creat
        :param fi: no idea
        :return:
        """
        path = path[1:]
        hash_id = hashing.HASHING_OBJ.difuse_hash(path)
        succ = hashing.HASHING_OBJ.succ(hash_id)
        host_ip = hashing.HASHING_OBJ.ip_table[succ]

        # if the successor is local id, create the file here
        if succ == hashing.HASHING_OBJ.id_hash:
            try:
                open(join(LOCAL_ROOT, path), 'xb').close()
            except OSError as ex:
                raise FuseOSError(ex.errno)
            else:
                self.fd += 1
                return self.fd

        # non local creation necessary
        logging.info(f'sending create {path} to {host_ip}')
        payload = {
            'filename': path
        }
        pkt = protocol.construct_packet(protocol.Verbs.CREATE,
                                        protocol.Status.OK,
                                        payload)
        try:
            header, payload = protocol.sock_send_recv(host_ip, pkt)
            if header.status == protocol.Status.EEXIST.name:
                raise FileExistsError
            if header.status == protocol.Status.EACCES.name:
                raise PermissionError
            if header.status != protocol.Status.OK.name:
                raise FuseOSError(errno.EIO)
        except FileExistsError:
            raise FuseOSError(errno.EEXIST)
        except PermissionError:
            raise FuseOSError(errno.EACCES)
        except ProtocolError:
            raise FuseOSError(errno.EIO)
        else:
            self.fd += 1
            return self.fd

    def destroy(self, path):
        """
        Destroy: send EXIT to bootstrap, XFER files to the successor of this node and destroy the FUSE mount
        """

        # notify bootstrap that we left
        try:
            req_pkt = protocol.construct_packet(protocol.Verbs.EXIT,
                                                protocol.Status.OK,
                                                {})
            protocol.sock_send_recv(self.bootstrap_ip, req_pkt, protocol.BOOTSTRAP_PORT)
        except ProtocolError:
            pass
        except IOError as ex:
            logging.exception(ex)
            pass

        # remove our self so relocate_files will not calculate our self as the succ for any files
        try:
            hashing.HASHING_OBJ.remove_node(hashing.HASHING_OBJ.id_hash)
        except ZeroDivisionError: # thrown if last node is exiting
            pass
        relocate_files(True)

        # destroy
        return super(Difuse, self).destroy(path)

    def getattr(self, path, fh=None):
        """
        stat/getattr syscall
        """
        if path == '/':
            return self._stat_dict(os.stat(LOCAL_ROOT))
        path = path[1:]
        if path in os.listdir(LOCAL_ROOT):
            stat = os.stat(join(LOCAL_ROOT, path))
            stat_dict = self._stat_dict(stat)
            stat_dict['st_uid'] = os.getuid()
            stat_dict['st_gid'] = os.getgid()
            return stat_dict

        host_ip = protocol.lookup(self.bootstrap_ip, path)

        try:
            pkt = protocol.construct_packet(protocol.Verbs.STAT_REQ,
                                            protocol.Status.OK,
                                            {'filename': path})
            header, payload = protocol.sock_send_recv(host_ip, pkt)
            logging.debug(f'getattr received {header}')
            if header.verb != protocol.Verbs.STAT_RES.name:
                raise FuseOSError(errno.EIO)
            if header.status == protocol.Status.ENOENT.name:
                raise FuseOSError(errno.ENOENT)
            stat = os.stat_result(payload['stat'])
            stat_dict = self._stat_dict(stat)
            stat_dict['st_uid'] = os.getuid()
            stat_dict['st_gid'] = os.getgid()
            return stat_dict
        except FuseOSError:
            raise
        except (ProtocolError, Exception) as ex:
            logging.exception(ex)
            raise FuseOSError(errno.EIO) from ex

    def getxattr(self, path, name, position=0):
        """
        getxattr: return '', xattrs not implemented.
        """
        return ''

    def listxattr(self, path):
        """
        listxattr: not implemented
        """
        pass

    def mkdir(self, path, mode):
        """
        mkdir: not implemented
        """
        pass

    def open(self, path, flags):
        """
        Open: if it is local, inc FD and return. it not local,
        do a lookup.
        """
        path = path[1:]
        if path in os.listdir():
            self.fd += 1
            return self.fd
        try:
            _host_ip = protocol.lookup(self.bootstrap_ip, path) # TODO
        except ProtocolError as ex:
            raise FuseOSError(errno.EIO)
        except FileNotFoundError:
            raise FuseOSError(errno.ENOENT)
        else:
            self.fd += 1
            return self.fd

    def read(self, path, size, offset, fh):
        """
        Read
        """
        path = path[1:]
        if path in os.listdir(LOCAL_ROOT):
            with open(join(LOCAL_ROOT, path), 'rb') as f:
                f.seek(offset)
                return f.read(size)
        try:
            host_ip = protocol.lookup(self.bootstrap_ip, path)
            req_payload = {
                'filename': path,
                'cnt': size,
                'offset': offset
            }
            req_pkt = protocol.construct_packet(protocol.Verbs.READ_REQ,
                                                protocol.Status.OK,
                                                req_payload)
            header, payload = protocol.sock_send_recv(host_ip, req_pkt)
            if header.status != protocol.Status.OK.name:
                if header.status == protocol.Status.ENOENT.name:
                    raise FileNotFoundError
                elif header.status == protocol.Status.EACCES.name:
                    raise PermissionError
            return bytes(payload['bytes'])
        except ProtocolError as ex:
            logging.exception(ex)
            raise FuseOSError(errno.EIO)
        except FileNotFoundError:
            raise FuseOSError(errno.ENOENT)
        except PermissionError:
            raise FuseOSError(errno.EACCES)

    def readdir(self, _path, fh):
        """
        readdir: broadcasts a READDIR_REQ to every node in the cluster and collects the results of all the READDIR_RES
        it receives
        """
        # create list of sockets to use for connection
        conns = [socket() for _ in range(len(hashing.HASHING_OBJ.ip_table.values()))]

        # broadcast READ DIR
        for conn, host_ip in zip(conns, hashing.HASHING_OBJ.ip_table.values()):
            try:
                conn.connect((host_ip, protocol.PORT))
                pkt = protocol.construct_packet(protocol.Verbs.READDIR_REQ,
                                                protocol.Status.OK,
                                                {})
                conn.send(pkt)
            except Exception as ex:
                logging.debug(f'error connecting to {host_ip}')
                logging.exception(ex)
                continue

        entries = []

        # collect the READDIR_RES'
        for conn in conns:
            try:
                header = protocol.HEADER.parse(conn.recv(protocol.HEADER.sizeof()))
                payload = json.loads(conn.recv(header.payload_size))
                if header.status != protocol.Status.OK.name:
                    continue
                entries += payload['entries']
            except (ConstructError, OSError, StreamError) as ex:
                logging.exception(ex)
                continue
            finally:
                conn.close()

        return ['.', '..'] + sorted(entries)

    def readlink(self, path):
        """
        Symlink not implemented. Canonical path of a file is its path.
        """
        return path

    def removexattr(self, path, name):
        """
        removexattr: not implemented.
        """
        pass

    def rename(self, old, new):
        """
        rename: not implemented.
        """
        pass

    def rmdir(self, path):
        """
        rmdir: not implemented
        """
        pass

    def statfs(self, path):
        """
        Return the stats of the local filesystem
        """
        path = path[1:]
        return os.statvfs(join(LOCAL_ROOT, path))

    def symlink(self, target, source):
        """
        symlinks not implemented
        """
        pass

    def truncate(self, path, length, fh=None):
        """
        Truncate
        """
        path = path[1:]
        if path in os.listdir(LOCAL_ROOT):
            os.truncate(join(LOCAL_ROOT, path), length)
        try:
            host_ip = protocol.lookup(self.bootstrap_ip, path)
        except FileNotFoundError:
            raise FuseOSError(errno.ENOENT)
        try:
            req_payload = {
                'filename': path,
                'len': length
            }
            req_pkt = protocol.construct_packet(protocol.Verbs.TRUNC_REQ,
                                                protocol.Status.OK,
                                                req_payload)
            header, payload = protocol.sock_send_recv(host_ip, req_pkt)
            if header.status != protocol.Status.OK.name:
                if header.status == protocol.Status.EACCES.name:
                    raise FuseOSError(errno.EACCES)
                elif header.status == protocol.Status.ENOENT.name:
                    raise FuseOSError(errno.ENOENT)
                else:
                    raise FuseOSError(errno.EIO)
        except ProtocolError:
            raise FuseOSError(errno.EIO)

    def unlink(self, path):
        """
        unlink: lookup the location of the file and send request to host. if local, remove.
        """
        path = path[1:]


        # check if local, if local send unlink req and return
        if path in os.listdir(LOCAL_ROOT):
            os.remove(join(LOCAL_ROOT, path))
            return

        req_payload = {
            'filename': path
        }
        req_pkt = protocol.construct_packet(protocol.Verbs.UNLINK_REQ,
                                            protocol.Status.OK,
                                            req_payload)
        # not local, lookup
        host_ip = protocol.lookup(self.bootstrap_ip, path)
        try:
            header, _ = protocol.sock_send_recv(host_ip, req_pkt)
            if header.status != protocol.Status.OK.name:
                if header.status == protocol.Status.ENOENT.name:
                    raise FuseOSError(errno.ENOENT)
                elif header.status == protocol.Status.EACCES.name:
                    raise FuseOSError(errno.EACCES)
                else:
                    raise FuseOSError(errno.EIO)
        except IOError:
            raise FuseOSError(errno.EIO)

    def utimens(self, path, times=None):
        """
        utimens: not implemented
        """
        pass

    def write(self, path, data, offset, fh):
        """
        Write
        """
        path = path[1:]
        if path in os.listdir(LOCAL_ROOT):
            path = join(LOCAL_ROOT, path)
            fd = os.open(path, os.O_WRONLY)
            os.lseek(fd, offset, os.SEEK_SET)
            writen = os.write(fd, data)
            os.close(fd)
            return writen
        try:
            host_ip = protocol.lookup(self.bootstrap_ip, path)
            req_payload = {
                'filename': path,
                'offset': offset,
                'bytes': list(data)
            }
            req_pkt = protocol.construct_packet(protocol.Verbs.WRITE_REQ,
                                                protocol.Status.OK,
                                                req_payload)
            header, payload = protocol.sock_send_recv(host_ip, req_pkt)
            logging.debug(header)
            if header.status != protocol.Status.OK.name:
                if header.status == protocol.Status.EACCES.name:
                    raise FuseOSError(errno.EACCES)
                elif header.status == protocol.Status.ENOENT.name:
                    raise FuseOSError(errno.ENOENT)
                else:
                    raise FuseOSError(errno.EIO)
            return payload['cnt']
        except (ProtocolError, KeyError):
            raise FuseOSError(errno.EIO)
