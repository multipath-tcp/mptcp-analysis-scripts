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

import common as co
import matplotlib
# Do not use any X11 backend
matplotlib.use('Agg')
import mptcp
import os
import os.path
import pickle
import sys


def check_in_list(dirpath, dirs):
    """ Check if dirpath is one of the dir in dirs, True if dirs is empty """
    if not dirs:
        return True
    return os.path.basename(dirpath) in dirs


def fetch_data(dir_exp, args):
    co.check_directory_exists(dir_exp)
    dico = {}
    for dirpath, dirnames, filenames in os.walk(dir_exp):
        if check_in_list(dirpath, args.dirs):
            for fname in filenames:
                try:
                    stat_file = open(os.path.join(dirpath, fname), 'r')
                    dico[fname] = pickle.load(stat_file)
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


def fetch_valid_data(dir_exp, args):
    connections = fetch_data(dir_exp, args)

    def ensures_smartphone_to_proxy():
        for fname in connections.keys():
            for conn_id in connections[fname].keys():
                if isinstance(connections[fname][conn_id], mptcp.MPTCPConnection):
                    inside = True
                    for flow_id, flow in connections[fname][conn_id].flows.iteritems():
                        if not flow.attr[co.DADDR].startswith('172.17.') and not flow.attr[co.DADDR] == co.IP_PROXY:
                            connections[fname].pop(conn_id, None)
                            inside = False
                            break
                    if inside:
                        for direction in co.DIRECTIONS:
                            # This is a fix for wrapping seq num
                            if connections[fname][conn_id].attr[direction][co.BYTES_MPTCPTRACE] < -1:
                                connections[fname][conn_id].attr[direction][co.BYTES_MPTCPTRACE] = 2 ** 32 + connections[fname][conn_id].attr[direction][co.BYTES_MPTCPTRACE]

    ensures_smartphone_to_proxy()
    return connections


def filter_connections(connections, min_bytes=None, max_bytes=None):
    filtered = {}

    for fname, data in connections.iteritems():
        filtered[fname] = {}
        for conn_id, conn in data.iteritems():
            if isinstance(conn, mptcp.MPTCPConnection):
                mptcp_bytes = conn.attr[co.S2D].get(co.BYTES_MPTCPTRACE, 0) + conn.attr[co.D2S].get(co.BYTES_MPTCPTRACE, 0)
                if (min_bytes and mptcp_bytes >= min_bytes) or (max_bytes and mptcp_bytes <= max_bytes):
                    filtered[fname][conn_id] = conn

    return filtered

# connections = filter_connections(connections)
