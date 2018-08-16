# DiFUSE: Distributed FUSE

Distributed filesystem written for network programming class.

Centralized P2P architecture.

Utilizes consistent hashing to distribute files when a node enters/leaves the cluster.

Custom protocol implemented.

# To use

## install dependencies

1. Download [fusepy](https://github.com/fusepy/fusepy)
2. Download [construct](https://construct.readthedocs.io/en/latest/)

## Spin up the Bootstrap node

The bootstrap node manages entering and exiting nodes into the cluster.

`./bootstrap.py [--threads THREADS]`

## Join the cluster with nodes 

`./node_main.py <bootstrap_ip> <mount_directory>`
