#! /usr/bin/python
# -*- coding: utf-8 -*-
#
#  Copyright 2015 Quentin De Coninck
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#
#  To install on this machine: matplotlib, numpy

from __future__ import print_function

import argparse
import matplotlib
# Do not use any X11 backend
matplotlib.use('Agg')
matplotlib.rcParams['pdf.fonttype'] = 42
matplotlib.rcParams['ps.fonttype'] = 42
import matplotlib.pyplot as plt
import numpy as np
import os
import sys

# Add root directory in Python path and be at the root
ROOT_DIR = os.path.abspath(os.path.join(".", os.pardir))
os.chdir(ROOT_DIR)
sys.path.append(ROOT_DIR)

import common as co
import common_graph as cog
import mptcp
import pickle
import tcp


def check_in_list(dirpath, dirs):
    """ Check if dirpath is one of the dir in dirs, True if dirs is empty """
    if not dirs:
        return True
    return os.path.basename(dirpath) in dirs


def fetch_data(dir_exp, args, filename_match=""):
    co.check_directory_exists(dir_exp)
    dico = {}
    for dirpath, dirnames, filenames in os.walk(dir_exp):
        if check_in_list(dirpath, args.dirs):
            for fname in filenames:
                if filename_match in fname:
                    try:
                        stat_file = open(os.path.join(dirpath, fname), 'r')
                        dico[fname] = pickle.load(stat_file)
                        stat_file.close()
                    except IOError as e:
                        print(str(e) + ': skip stat file ' + fname, file=sys.stderr)
    return dico


def fetch_and_process_data(dir_exp, args, filename_match, funct, *fargs):
    co.check_directory_exists(dir_exp)
    dico = {}
    for dirpath, dirnames, filenames in os.walk(dir_exp):
        if check_in_list(dirpath, args.dirs):
            for fname in filenames:
                if filename_match in fname:
                    try:
                        stat_file = open(os.path.join(dirpath, fname), 'r')
                        conns = pickle.load(stat_file)
                        for conn_id in conns:
                            if isinstance(conns[conn_id], mptcp.MPTCPConnection):
                                for flow_id, flow in conns[conn_id].flows.iteritems():
                                    if not [x for x in co.PREFIX_IP_PROXY if flow.attr[co.DADDR].startswith(x)] and not flow.attr[co.DADDR] in co.IP_PROXY:
                                        conns.pop(conn_id, None)
                                        break
                            elif isinstance(conns[conn_id], tcp.TCPConnection):
                                if not [x for x in co.PREFIX_IP_PROXY if conns[conn_id].flow.attr[co.DADDR].startswith(x)] and not conns[conn_id].flow.attr[co.DADDR] in co.IP_PROXY:
                                    conns.pop(conn_id, None)
                                    break
                        funct(fname, conns, *fargs)
                        stat_file.close()
                    except IOError as e:
                        print(str(e) + ': skip stat file ' + fname, file=sys.stderr)
    return dico


def get_multiflow_connections(connections):
    multiflow_connections = {}
    singleflow_connections = {}
    for fname, conns_fname in connections.iteritems():
        for conn_id, conn in conns_fname.iteritems():
            if isinstance(conn, mptcp.MPTCPConnection):
                if len(conn.flows) > 1:
                    if fname not in multiflow_connections:
                        multiflow_connections[fname] = {}
                    multiflow_connections[fname][conn_id] = conn
                else:
                    if fname not in singleflow_connections:
                        singleflow_connections[fname] = {}
                    singleflow_connections[fname][conn_id] = conn

    return multiflow_connections, singleflow_connections


def fetch_valid_data(dir_exp, args, filename_match=""):
    connections = fetch_data(dir_exp, args, filename_match=filename_match)

    def ensures_smartphone_to_proxy():
        for fname in connections.keys():
            for conn_id in connections[fname].keys():
                if isinstance(connections[fname][conn_id], mptcp.MPTCPConnection):
                    inside = True
                    for flow_id, flow in connections[fname][conn_id].flows.iteritems():
                        if not [x for x in co.PREFIX_IP_PROXY if flow.attr[co.DADDR].startswith(x)] and not flow.attr[co.DADDR] in co.IP_PROXY:
                            connections[fname].pop(conn_id, None)
                            inside = False
                            break
                    if inside:
                        for direction in co.DIRECTIONS:
                            # This is a fix for wrapping seq num
                            if connections[fname][conn_id].attr[direction].get(co.BYTES_MPTCPTRACE, -2 ** 32) < -1:
                                connections[fname][conn_id].attr[direction][co.BYTES_MPTCPTRACE] = 2 ** 32 + connections[fname][conn_id].attr[direction].get(co.BYTES_MPTCPTRACE, -2 ** 32)

    ensures_smartphone_to_proxy()

    # Very strange cases, mptcptrace has difficult to analyze this now
    if 'dump_20150408_14121313' in connections:
        connections['dump_20150408_14121313'].pop(25581, None)
    if 'dump_20150308_21403706' in connections:
        connections['dump_20150308_21403706'].pop(5154, None)
        connections['dump_20150308_21403706'].pop(19983, None)
    if 'dump_20150408_14121302' in connections:
        connections['dump_20150408_14121302'].pop(7004, None)

    return connections


def filter_connections(connections, min_bytes=None, max_bytes=None):
    filtered = {}

    for fname, data in connections.iteritems():
        filtered[fname] = {}
        for conn_id, conn in data.iteritems():
            if isinstance(conn, mptcp.MPTCPConnection):
                mptcp_bytes = conn.attr[co.C2S].get(co.BYTES_MPTCPTRACE, 0) + conn.attr[co.S2C].get(co.BYTES_MPTCPTRACE, 0)
                if (min_bytes and mptcp_bytes >= min_bytes) or (max_bytes and mptcp_bytes <= max_bytes):
                    filtered[fname][conn_id] = conn

    return filtered

# connections = filter_connections(connections)
