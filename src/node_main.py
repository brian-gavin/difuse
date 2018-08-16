#! /usr/bin/env python3
from node_const import LOCAL_ROOT
from node_server import DifuseServer
from node_fuse import Difuse
import logging
from fuse import FUSE
import argparse
import sys
import os
from threading import Thread
from os.path import expanduser


def server_main(args):
    server = DifuseServer(args.bootstrap_ip, args.mount)
    server.serve()


def main(args):
    """
    Main routine
    """
    try:
        os.mkdir(LOCAL_ROOT)
    except FileExistsError:
        pass
    try:
        os.mkdir(expanduser(args.mount))
    except FileExistsError:
        pass
    logging.basicConfig(level=logging.DEBUG)
    Thread(target=server_main, args=[args], name='Server Thread', daemon=True).start()
    FUSE(Difuse(args.bootstrap_ip), args.mount, foreground=True)
    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='DiFUSE Node')
    parser.add_argument('bootstrap_ip', help='IP Addresss of bootstrap node')
    parser.add_argument('mount', help='Mount point of local filesystem')
    sys.exit(main(parser.parse_args()))
