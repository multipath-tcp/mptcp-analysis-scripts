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
import common as co
import common_graph as cog
import matplotlib
# Do not use any X11 backend
matplotlib.use('Agg')
matplotlib.rcParams['pdf.fonttype'] = 42
matplotlib.rcParams['ps.fonttype'] = 42
import matplotlib.pyplot as plt
import mptcp
import numpy as np
import os
import tcp

##################################################
##                  ARGUMENTS                   ##
##################################################

parser = argparse.ArgumentParser(
    description="Summarize stat files generated by analyze")
parser.add_argument("-s",
                    "--stat", help="directory where the stat files are stored", default=co.DEF_STAT_DIR + '_' + co.DEF_IFACE)
parser.add_argument('-S',
                    "--sums", help="directory where the summary graphs will be stored", default=co.DEF_SUMS_DIR + '_' + co.DEF_IFACE)
parser.add_argument("-d",
                    "--dirs", help="list of directories to aggregate", nargs="+")

args = parser.parse_args()
stat_dir_exp = os.path.abspath(os.path.expanduser(args.stat))
sums_dir_exp = os.path.abspath(os.path.expanduser(args.sums))
co.check_directory_exists(sums_dir_exp)

##################################################
##                 GET THE DATA                 ##
##################################################

connections = cog.fetch_valid_data(stat_dir_exp, args)
multiflow_connections, singleflow_connections = cog.get_multiflow_connections(connections)

##################################################
##               PLOTTING RESULTS               ##
##################################################

nb_conns = 0
nb_subflows = 0
nb_unused = 0
nb_addi_sf = 0
nb_unused_addi_sf = 0
nb_unused_rst = 0
nb_after_duration = 0

for fname, conns in multiflow_connections.iteritems():
    for conn_id, conn in conns.iteritems():
        nb_conns += 1
        for flow_id, flow in conn.flows.iteritems():
            nb_subflows += 1
            if not flow_id == 0:
                nb_addi_sf += 1

            if flow.attr[co.S2D].get(co.BYTES, 0) == 0 and flow.attr[co.D2S].get(co.BYTES, 0) == 0:
                nb_unused += 1
                if not flow_id == 0:
                    nb_unused_addi_sf += 1

                if not flow.attr[co.S2D].get(co.NB_RST, 0) == 0 or not flow.attr[co.D2S].get(co.NB_RST, 0) == 0:
                    nb_unused_rst += 1

                if co.START in flow.attr and flow.attr[co.START] >= conn.attr[co.START] + conn.attr[co.DURATION]:
                    nb_after_duration += 1

print("NB CONNS", nb_conns)
print("NB SUBFLOWS", nb_subflows)
print("NB UNUSED", nb_unused)
print("NB ADDI SF", nb_addi_sf)
print("NB UNUSED ADDI SF", nb_unused_addi_sf)
print("NB UNUSED RST", nb_unused_rst)
print("NB AFTER DURATION", nb_after_duration)
