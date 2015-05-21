#! /usr/bin/python
# -*- coding: utf-8 -*-
#
#  Copyright 2015 Matthieu Baerts & Quentin De Coninck
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

##################################################
##                   IMPORTS                    ##
##################################################

import argparse
import bisect
import common as co
import glob
import matplotlib
# Do not use any X11 backend
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import mptcp
import numpy as np
import os
import os.path
import pickle
import sys
import tcp

##################################################
##                  ARGUMENTS                   ##
##################################################

parser = argparse.ArgumentParser(
    description="Summarize sequence number together in one graph")
parser.add_argument("-s",
                    "--stat", help="directory where the stat files are stored", default=co.DEF_STAT_DIR+'_'+co.DEF_IFACE)
parser.add_argument('-S',
                    "--sums", help="directory where the summary graphs will be stored", default=co.DEF_SUMS_DIR+'_'+co.DEF_IFACE)
parser.add_argument("-d",
                    "--dirs", help="list of directories to aggregate", nargs="+")
parser.add_argument("-c",
                    "--csv", help="directory where csvs/xpls are located")

args = parser.parse_args()

stat_dir_exp = os.path.abspath(os.path.expanduser(args.stat))
sums_dir_exp = os.path.abspath(os.path.expanduser(args.sums))
csv_dir_exp = os.path.abspath(os.path.expanduser(args.csv))

co.check_directory_exists(sums_dir_exp)

def check_in_list(dirpath, dirs):
    """ Check if dirpath is one of the dir in dirs, True if dirs is empty """
    if not dirs:
        return True
    return os.path.basename(dirpath) in dirs


def fetch_data(dir_exp):
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

connections = fetch_data(stat_dir_exp)


def is_reverse_connection(csv_fname):
    first_underscore_index = csv_fname.rindex("_")
    second_underscore_index = csv_fname[:first_underscore_index].rindex("_")
    third_underscore_index = csv_fname[:second_underscore_index].rindex("_")
    return csv_fname[third_underscore_index + 1:second_underscore_index] == "s2c"


def seq_d2s_all_connections(time_loss=1.5):
    for fname, conns in connections.iteritems():
        seqs = {co.WIFI: [], co.CELL: []}
        start_connections = []
        retrans_rto = {co.WIFI: [], co.CELL: []}
        retrans_frt = {co.WIFI: [], co.CELL: []}
        retrans_rec = {co.WIFI: [], co.CELL: []}
        retrans_rto_plot = {co.WIFI: [], co.CELL: []}
        retrans_frt_plot = {co.WIFI: [], co.CELL: []}
        retrans_rec_plot = {co.WIFI: [], co.CELL: []}
        conn_event = {co.WIFI: [], co.CELL: []}

        if fname.startswith('mptcp'):
            start_subflows = {co.WIFI: [], co.CELL: []}
            min_start = float('inf')
            for conn_id, conn in conns.iteritems():
                for flow_id, flow in conn.flows.iteritems():
                    min_start = min(min_start, flow.attr.get(co.START, float('inf')))

            offset_duration = {}
            for conn_id, conn in conns.iteritems():
                offset_duration[conn_id] = {}
                for flow_id, flow in conn.flows.iteritems():
                    offset_duration[conn_id][flow_id] = flow.attr.get(co.START, float('inf')) - min_start

            for xpl_path in glob.glob(os.path.join(csv_dir_exp, fname + '_*.xpl')):
                xpl_fname = os.path.basename(xpl_path)
                if 'tsg' not in xpl_fname:
                    continue
                xpl_fullpath = os.path.abspath(os.path.expanduser(xpl_path))
                # Preprocessing, avoid wasting time with not interesting files
                flow_name, from_server_to_smartphone = tcp.get_flow_name(xpl_fname)
                if not from_server_to_smartphone:
                    continue

                # Opening of the file
                try:
                    xpl_file = open(xpl_fullpath)
                    data = xpl_file.readlines()
                    xpl_file.close()
                except IOError as e:
                    print(str(e))
                    continue

                conn = None
                conn_id = None
                flow_id = None

                for conn_i, connection in conns.iteritems():
                    for flow_i, flow in connection.flows.iteritems():
                        if flow.subflow_id == flow_name:
                            conn = connection
                            conn_id = conn_i
                            flow_id = flow_i
                            break
                    if conn and flow_id:
                        break

                if not conn:
                    continue

                # Now process the file
                start_connections.append(conn.attr[co.START] - min_start)
                interface = conn.flows[flow_id].attr[co.IF]
                conn_event[interface].append((conn.attr[co.START] - min_start, 'start'))
                start_subflows[interface].append(conn.flows[flow_id].attr[co.START] - min_start)

                if offset_duration[conn_id][flow_id] == float('inf'):
                    print('Skipped', fname, conn_id, flow_id, flow_name, conn.attr)
                    continue

                last_time = None
                is_white = False
                for line in data:
                    if is_white and (line.startswith("uarrow") or line.startswith("diamond")):
                        split_line = line.split(" ")
                        # if ((not split_line[0] == "diamond") or (len(split_line) == 4 and "white" in split_line[3])):
                        time = float(split_line[1])
                        last_time = time
                        seqs[interface].append([time + offset_duration[conn_id][flow_id], int(split_line[2]), flow_name])
                    elif len(line.split(" ")) == 1:
                        if line.startswith("white"):
                            is_white = True
                        else:
                            is_white = False

                if last_time:
                    conn_event[interface].append((last_time + offset_duration[conn_id][flow_id], 'end'))
                else:
                    # Opened too shortly
                    conn_event[interface].append((conn.attr[co.START] - min_start + 0.010000, 'end'))

                for reinject_time, reinject_type in conn.flows[flow_id].attr[co.D2S][co.TCPCSM_RETRANS]:
                    ts_int = int(reinject_time.split('.')[0])
                    ts_dec = float('.' + reinject_time.split('.')[1])
                    ts_offset_int = ts_int - int(min_start)
                    ts_offset_dec = ts_dec - (min_start - int(min_start))
                    ts_offset = ts_offset_int + ts_offset_dec
                    if reinject_type == 'RTO':
                        retrans_rto[interface].append(ts_offset)
                    elif reinject_type in ['FRETX', 'MS_FRETX', 'SACK_FRETX', 'BAD_FRETX']:
                        retrans_frt[interface].append(ts_offset)
                    elif reinject_type in ['LOSS_REC', 'UNEXP_FREC', 'UNNEEDED']:
                        retrans_rec[interface].append(ts_offset)

            print("WIFI size", len(seqs[co.WIFI]))
            print("CELL size", len(seqs[co.CELL]))
            # Now put all together on a same graph
            offsets = {co.WIFI: {}, co.CELL: {}}
            tot_offset = {co.WIFI: 0, co.CELL: 0}
            seqs_plot = {co.WIFI: [], co.CELL: []}
            for ith, seqs_ith in seqs.iteritems():
                seqs_sort = sorted(seqs_ith, key=lambda elem: elem[0])
                for elem in seqs_sort:
                    if elem[2] not in offsets[ith]:
                        offsets[ith][elem[2]] = elem[1]
                        seqs_plot[ith].append((elem[0], tot_offset[ith]))
                        if tot_offset[ith] < 0 or elem[1] < 0:
                            print("NEGATIVE START", ith, elem[1], tot_offset[ith])
                    else:
                        if tot_offset[ith] + (elem[1] - offsets[ith][elem[2]]) < 0:
                            print(offsets)
                            print("NEGATIVE", ith, elem[1], tot_offset[ith], offsets[ith][elem[2]], tot_offset[ith] + (elem[1] - offsets[ith][elem[2]]))
                        seqs_plot[ith].append((elem[0], tot_offset[ith] + (elem[1] - offsets[ith][elem[2]])))
                        tot_offset[ith] += elem[1] - offsets[ith][elem[2]]
                        offsets[ith][elem[2]] = elem[1]

                # If needed, insert 0s in curves to show loss of connectivity
                sorted_events = sorted(conn_event[ith], key=lambda elem: elem[0])
                print(sorted_events)
                counter = 0
                sorted_event_plot = [(0.0, 0)]
                x_data = [x for x, y in seqs_plot[ith]]
                for event_time, event in sorted_events:
                    if event == 'start':
                        if counter == 0:
                            sorted_event_plot.append((event_time - 0.005000, 0))
                        counter += 1
                    elif event == 'end':
                        if counter == 0:
                            print("Strange...")
                        else:
                            counter -= 1
                            if counter == 0:
                                index = bisect.bisect_left(x_data, event_time + 0.004999)
                                if index < len(seqs_plot[ith]) - 1:
                                    sorted_event_plot.append((event_time + 0.004999, seqs_plot[ith][index][1]))
                                    sorted_event_plot.append((event_time + 0.005000, 0))

                improved_seqs_plot = []
                previous_elem = None
                for elem in seqs_plot[ith]:
                    if len(improved_seqs_plot) >= 1 and elem[1] - previous_elem[1] < 2 and elem[0] - previous_elem[0] >= 1.0:
                        improved_seqs_plot.append((previous_elem[0] + 0.001000, 0))
                        improved_seqs_plot.append((elem[0] - 0.001000, 0))
                    previous_elem = elem
                    improved_seqs_plot.append(elem)

                for retrans_ts in retrans_rto[ith]:
                    x_data = [x for x, y in seqs_plot[ith]]
                    index = min(bisect.bisect_left(x_data, retrans_ts), len(x_data) - 1)
                    retrans_rto_plot[ith].append((retrans_ts, seqs_plot[ith][index][1]))

                for retrans_ts in retrans_frt[ith]:
                    x_data = [x for x, y in seqs_plot[ith]]
                    index = min(bisect.bisect_left(x_data, retrans_ts), len(x_data) - 1)
                    retrans_frt_plot[ith].append((retrans_ts, seqs_plot[ith][index][1]))

                for retrans_ts in retrans_rec[ith]:
                    x_data = [x for x, y in seqs_plot[ith]]
                    index = min(bisect.bisect_left(x_data, retrans_ts), len(x_data) - 1)
                    retrans_rec_plot[ith].append((retrans_ts, seqs_plot[ith][index][1]))

                seqs_plot[ith] = sorted(improved_seqs_plot + sorted_event_plot, key=lambda elem: elem[0])

            # start_ts = min(seqs_plot[co.WIFI][0][0], seqs_plot[co.CELL][0][0])
            fig, ax = plt.subplots()
            ax.plot([x[0] for x in seqs_plot[co.WIFI]], [x[1] for x in seqs_plot[co.WIFI]], 'b-', label="WiFi")
            ax.plot([x[0] for x in seqs_plot[co.CELL]], [x[1] for x in seqs_plot[co.CELL]], 'r-', label="Cellular")
            for ith in [co.WIFI, co.CELL]:
                if ith == co.WIFI:
                    ax.plot([x[0] for x in retrans_rto_plot[ith]], [x[1] for x in retrans_rto_plot[ith]], 'cd', label="Retr RTO", alpha=0.33)
                    ax.plot([x[0] for x in retrans_frt_plot[ith]], [x[1] for x in retrans_frt_plot[ith]], 'md', label="Retr FRT", alpha=0.33)
                    ax.plot([x[0] for x in retrans_rec_plot[ith]], [x[1] for x in retrans_rec_plot[ith]], 'yd', label="Retr REC", alpha=0.33)
                else:
                    ax.plot([x[0] for x in retrans_rto_plot[ith]], [x[1] for x in retrans_rto_plot[ith]], 'cd', alpha=0.33)
                    ax.plot([x[0] for x in retrans_frt_plot[ith]], [x[1] for x in retrans_frt_plot[ith]], 'md', alpha=0.33)
                    ax.plot([x[0] for x in retrans_rec_plot[ith]], [x[1] for x in retrans_rec_plot[ith]], 'yd', alpha=0.33)

            max_wifi = max([x[1] for x in seqs_plot[co.WIFI]]) if len(seqs_plot[co.WIFI]) > 0 else 10
            max_cell = max([x[1] for x in seqs_plot[co.CELL]]) if len(seqs_plot[co.WIFI]) > 0 else 10
            ax.plot(start_subflows[co.WIFI], [max_wifi for x in start_subflows[co.WIFI]], 'bx', label="Start SF W")
            ax.plot(start_subflows[co.CELL], [max_cell for x in start_subflows[co.CELL]], 'rx', label="Start SF C")
            ax.plot(start_connections, [10 for x in start_connections], 'gx', label="Start co")
            # Shrink current axis by 20%
            box = ax.get_position()
            ax.set_position([box.x0, box.y0, box.width * 0.8, box.height])

            # Put a legend to the right of the current axis
            ax.legend(loc='center left', bbox_to_anchor=(1, 0.5), fontsize='large')
            plt.xlim(xmin=0.0)
            plt.xlabel("Time", fontsize=18)
            plt.ylabel("Bytes", fontsize=18)
            plt.savefig(os.path.join(sums_dir_exp, fname + '.pdf'))
            plt.close('all')

        elif fname.startswith('tcp'):
            min_start = float('inf')
            for conn_id, conn in conns.iteritems():
                min_start = min(min_start, conn.flow.attr.get(co.START, float('inf')))

            for xpl_path in glob.glob(os.path.join(csv_dir_exp, fname + '_*.xpl')):
                xpl_fname = os.path.basename(xpl_path)
                # Preprocessing, avoid wasting time with not interesting files
                conn_id, from_server_to_smartphone = tcp.get_flow_name(xpl_fname)
                if not from_server_to_smartphone:
                    continue

                # Opening of the file
                try:
                    xpl_file = open(xpl_path)
                    data = xpl_file.readlines()
                    xpl_file.close()
                except IOError as e:
                    print(str(e))
                    continue

                # Now process the file
                conn = connections[fname][conn_id]
                start_connections.append(conn.flow.attr[co.START] - min_start)
                offset = conn.flow.attr[co.START] - min_start
                interface = conn.flow.attr[co.IF]
                conn_event[interface].append((conn.flow.attr[co.START] - min_start, 'start'))
                last_time = None
                is_white = False
                for line in data:
                    if is_white and (line.startswith("uarrow") or line.startswith("diamond")):
                        split_line = line.split(" ")
                        # if ((not split_line[0] == "diamond") or (len(split_line) == 4 and "white" in split_line[3])):
                        time = float(split_line[1])
                        last_time = time
                        seqs[interface].append([time, int(split_line[2]) + offset, conn_id])
                    elif len(line.split(" ")) == 1:
                        if line.startswith("white"):
                            is_white = True
                        else:
                            is_white = False

                if last_time:
                    conn_event[interface].append((last_time + offset, 'end'))
                else:
                    # Opened too shortly
                    conn_event[interface].append((conn.flow.attr[co.START] - min_start + 0.010000, 'end'))

                for reinject_time, reinject_type in conn.flow.attr[co.D2S].get(co.TCPCSM_RETRANS, []):
                    ts_int = int(reinject_time.split('.')[0])
                    ts_dec = float('.' + reinject_time.split('.')[1])
                    ts_offset_int = ts_int - int(min_start)
                    ts_offset_dec = ts_dec - (min_start - int(min_start))
                    ts_offset = ts_offset_int + ts_offset_dec
                    if reinject_type == 'RTO':
                        retrans_rto[interface].append(ts_offset)
                    elif reinject_type in ['FRETX', 'MS_FRETX', 'SACK_FRETX', 'BAD_FRETX']:
                        retrans_frt[interface].append(ts_offset)
                    elif reinject_type in ['LOSS_REC', 'UNEXP_FREC', 'UNNEEDED']:
                        retrans_rec[interface].append(ts_offset)

            # Now put all togetger on a same graph
            offsets = {}
            tot_offset = {co.WIFI: 0, co.CELL: 0}
            seqs_plot = {co.WIFI: [], co.CELL: []}
            for ith, seqs_ith in seqs.iteritems():
                seqs_sort = sorted(seqs_ith, key=lambda elem: elem[0])
                for elem in seqs_sort:
                    if elem[2] not in offsets:
                        offsets[elem[2]] = elem[1]
                        seqs_plot[ith].append((elem[0], tot_offset[ith]))
                    else:
                        seqs_plot[ith].append((elem[0], tot_offset[ith] + (elem[1] - offsets[elem[2]])))
                        tot_offset[ith] += elem[1] - offsets[elem[2]]
                        offsets[elem[2]] = elem[1]

                # If needed, insert 0s in curves to show loss of connectivity
                sorted_events = sorted(conn_event[ith], key=lambda elem: elem[0])
                counter = 0
                sorted_event_plot = [(0.0, 0)]
                x_data = [x for x, y in seqs_plot[ith]]
                for event_time, event in sorted_events:
                    if event == 'start':
                        if counter == 0:
                            sorted_event_plot.append((event_time - 0.005000, 0))
                            index = bisect.bisect_left(x_data, event_time - 0.003000)
                            sorted_event_plot.append((event_time - 0.003000, seqs_plot[ith][index][1]))
                        counter += 1
                    elif event == 'end':
                        if counter == 0:
                            print("Strange...")
                        else:
                            counter -= 1
                            if counter == 0:
                                index = bisect.bisect_left(x_data, event_time + 0.004999)
                                if index < len(seqs_plot[ith]) - 2:
                                    sorted_event_plot.append((event_time + 0.004999, seqs_plot[ith][index][1]))
                                    sorted_event_plot.append((event_time + 0.005000, 0))

                improved_seqs_plot = []
                previous_elem = None
                for elem in seqs_plot[ith]:
                    if len(improved_seqs_plot) >= 1 and elem[1] - previous_elem[1] < 2 and elem[0] - previous_elem[0] >= 1.0:
                        improved_seqs_plot.append((previous_elem[0] + 0.001000, 0))
                        improved_seqs_plot.append((elem[0] - 0.001000, 0))
                    previous_elem = elem
                    improved_seqs_plot.append(elem)

                for retrans_ts in retrans_rto[ith]:
                    x_data = [x for x, y in seqs_plot[ith]]
                    index = min(bisect.bisect_left(x_data, retrans_ts), len(x_data) - 1)
                    retrans_rto_plot[ith].append((retrans_ts, seqs_plot[ith][index][1]))

                for retrans_ts in retrans_frt[ith]:
                    x_data = [x for x, y in seqs_plot[ith]]
                    index = min(bisect.bisect_left(x_data, retrans_ts), len(x_data) - 1)
                    retrans_frt_plot[ith].append((retrans_ts, seqs_plot[ith][index][1]))

                for retrans_ts in retrans_rec[ith]:
                    x_data = [x for x, y in seqs_plot[ith]]
                    index = min(bisect.bisect_left(x_data, retrans_ts), len(x_data) - 1)
                    retrans_rec_plot[ith].append((retrans_ts, seqs_plot[ith][index][1]))

                seqs_plot[ith] = sorted(improved_seqs_plot + sorted_event_plot, key=lambda elem: elem[0])

            # start_ts = min(seqs_plot[co.WIFI][0][0], seqs_plot[co.CELL][0][0])
            fig, ax = plt.subplots()
            ax.plot([x[0] for x in seqs_plot[co.WIFI]], [x[1] for x in seqs_plot[co.WIFI]], 'b-', label="WiFi")
            ax.plot([x[0] for x in seqs_plot[co.CELL]], [x[1] for x in seqs_plot[co.CELL]], 'r-', label="Cellular")
            for ith in [co.WIFI, co.CELL]:
                if ith == co.WIFI:
                    ax.plot([x[0] for x in retrans_rto_plot[ith]], [x[1] for x in retrans_rto_plot[ith]], 'cd', label="Retr RTO", alpha=0.33)
                    ax.plot([x[0] for x in retrans_frt_plot[ith]], [x[1] for x in retrans_frt_plot[ith]], 'md', label="Retr FRT", alpha=0.33)
                    ax.plot([x[0] for x in retrans_rec_plot[ith]], [x[1] for x in retrans_rec_plot[ith]], 'yd', label="Retr REC", alpha=0.33)
                else:
                    ax.plot([x[0] for x in retrans_rto_plot[ith]], [x[1] for x in retrans_rto_plot[ith]], 'cd', alpha=0.33)
                    ax.plot([x[0] for x in retrans_frt_plot[ith]], [x[1] for x in retrans_frt_plot[ith]], 'md', alpha=0.33)
                    ax.plot([x[0] for x in retrans_rec_plot[ith]], [x[1] for x in retrans_rec_plot[ith]], 'yd', alpha=0.33)
            ax.plot(start_connections, [10 for x in start_connections], 'gx', label="Start co")
            # Shrink current axis by 20%
            box = ax.get_position()
            ax.set_position([box.x0, box.y0, box.width * 0.8, box.height])

            # Put a legend to the right of the current axis
            ax.legend(loc='center left', bbox_to_anchor=(1, 0.5), fontsize='large')
            plt.xlim(xmin=0.0)
            plt.xlabel("Time", fontsize=18)
            plt.ylabel("Bytes", fontsize=18)
            plt.savefig(os.path.join(sums_dir_exp, fname + '.pdf'))
            plt.close('all')

seq_d2s_all_connections()


def collect_seq():
    seqs = {}
    for csv_path in glob.glob(os.path.join(csv_dir_exp, '*.csv')):
        csv_fname = os.path.basename(csv_path)
        try:
            csv_file = open(csv_path)
            data = csv_file.readlines()
            csv_file.close()
        except IOError as e:
            print(str(e))
            continue

        seqs_csv = []

        for line in data:
            split_line = line.split(',')
            if len(split_line) == 6:
                if int(split_line[3]) == 0:
                    # ACK
                    timestamp = float(split_line[0])
                    seq_ack = int(split_line[1])
                    flow_id = int(split_line[2]) - 1
                    # is_ack = True # int(split_line[3]) == 0
                    # dummy = int(split_line[4])
                    # dummy_2 = int(split_line[5])
                    seqs_csv.append((timestamp, seq_ack, flow_id))

                elif int(split_line[3]) == 1:
                    # MAP
                    timestamp = float(split_line[0])
                    seq_start = int(split_line[1])
                    flow_id = int(split_line[2]) - 1
                    # is_ack = False # int(split_line[3]) == 1
                    seq_end = int(split_line[4])
                    reinject_flow = int(split_line[5]) - 1 # If not negative, the flow where packet was first seen
                    seqs_csv.append((timestamp, seq_start, flow_id, seq_end, reinject_flow))

        seqs[csv_fname] = seqs_csv

    return seqs
