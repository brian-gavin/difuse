"""
Holds shared / constant data between both sides of a Node
"""
from os.path import expanduser, join
import os
import logging
import hashing
from hashing import Hashing
import protocol

LOCAL_ROOT = expanduser('~/.difuse')

def relocate_files(relocate_all=False):
    """
    Scans the LOCAL_ROOT directory for files that need to be relocated and sends XFER_RES to each node where files
    should be transferred.
    :relocate_all: Default false. If true, all files on local root will be transferred to the successor
    :return: None
    """
    # table that maps an ID hash to a list of dictionary to send
    xfer_res_table = {id_hash: [] for id_hash in hashing.HASHING_OBJ.hash_unit}

    # build xfer res table for each file in the local root
    for filename in os.listdir(LOCAL_ROOT):
        file_hash = Hashing.difuse_hash(filename)
        try:
            file_succ = Hashing.succ(file_hash)
        except ZeroDivisionError: # thrown if last node exiting
            return
        logging.debug(f'filename: {filename} | file_hash: {file_hash}')
        if relocate_all or file_succ != hashing.HASHING_OBJ.id_hash:
            try:
                with open(join(LOCAL_ROOT, filename), 'rb') as f:
                    file_bytes = f.read()
                    xfer_res_table[file_succ].append({
                        'filename': filename,
                        'bytes': list(file_bytes)
                    })
            except Exception as ex:
                logging.exception(ex)
                pass
    # send the XFER_RES
    for id_hash, xfer_list in xfer_res_table.items():
        # no files to transfer, do not send anything
        if not xfer_list:
            continue

        conn_ip = hashing.HASHING_OBJ.ip_table[id_hash]
        logging.info(f'relocating {xfer_list} to {conn_ip}')
        xfer_res_pkt = protocol.construct_packet(protocol.Verbs.XFER, protocol.Status.OK, {'files': xfer_list})
        try:
            protocol.sock_send_recv(conn_ip, xfer_res_pkt)
        except Exception as ex:
            logging.exception(ex)
        else:
            for xfer_file in xfer_list:
                os.remove(join(LOCAL_ROOT, xfer_file['filename']))

