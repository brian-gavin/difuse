# DiFUSE: Distributed FUSE

### Authors: Brian Gavin and [Ngan Nguyen](http://ngan-nguyen.xyz/)

Distributed filesystem written for network programming class.

Centralized P2P architecture.

Utilizes consistent hashing to distribute files when a node enters/leaves the cluster.

Custom protocol implemented.

# To use

## install dependencies

1. Download [fusepy](https://github.com/fusepy/fusepy)
2. Download [construct](https://construct.readthedocs.io/en/latest/)

## Spin up the Bootstrap node

The bootstrap node manages the entrance and exit of nodes in the cluster.

`./bootstrap.py [--threads THREADS]`

## Join the cluster with nodes 

The nodes are what manages the mounted filesystem and all the communication.

`./node_main.py <bootstrap_ip> <mount_directory>`
