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
#  Contains code related to the processing of MPTCP traces

from __future__ import print_function

##################################################
##                   IMPORTS                    ##
##################################################

import common as co
import glob
import numpy as np
import os
import shutil
import subprocess
import sys
import tcp
import tempfile

##################################################
##                  CONSTANTS                   ##
##################################################

# mptcptrace file identifier in csv filename for sequence number informations
MPTCP_SEQ_FNAME = '_seq_'
# mptcptrace file identifier in csv filename for subflow number informations
MPTCP_SF_FNAME = '_sf_'
# mptcptrace file identifier in csv filename for rtt informations
MPTCP_RTT_FNAME = '_rtt_seq_'
# mptcptrace stats files prefix in csv filename of a subflow
MPTCP_STATS_PREFIX = 'stats_'
# mptcptrace file identifier in csv filename for gput information
MPTCP_GPUT_FNAME = 'gput'
# mptcptrace file identifier in csv filename for acksize information
MPTCP_ACKSIZE_FNAME = '_acksize_'


##################################################
##                  EXCEPTIONS                  ##
##################################################


class MPTCPTraceError(Exception):
    pass

##################################################
##           CONNECTION DATA RELATED            ##
##################################################


class MPTCPSubFlow(co.BasicFlow):

    """ Represent a MPTCP subflow """
    subflow_id = ""

    def __init__(self, sid):
        super(MPTCPSubFlow, self).__init__()
        self.subflow_id = sid


class MPTCPConnection(co.BasicConnection):

    """ Represent a MPTCP connection """
    flows = {}

    def __init__(self, cid):
        super(MPTCPConnection, self).__init__(cid)
        self.flows = {}


def extract_flow_data(out_file):
    """ Given an (open) file, return a dictionary of as many elements as there are mptcp flows """
    # Return at the beginning of the file
    out_file.seek(0)
    data = out_file.readlines()
    connections = {}
    current_connection = False
    for line in data:
        # Case 1: line start with MPTCP connection
        if line.startswith("MPTCP connection"):
            # A typical line: MPTCP connection 0 with id 2
            words = line.split()
            current_connection = words[-1]
            connections[current_connection] = MPTCPConnection(current_connection)

        # Case 2: line for a subflow
        elif current_connection is not False and line.startswith("\tSubflow"):
            # A typical line:
            #   Subflow 0 with wscale : 6 0 IPv4 sport 59570 dport 443 saddr
            # 37.185.171.74 daddr 194.78.99.114
            words = line.split()
            sub_flow_id = words[1]
            subflow = MPTCPSubFlow(sub_flow_id)
            index_wscale = words.index("wscale")
            subflow.attr[
                co.WSCALESRC] = words[index_wscale + 2]
            subflow.attr[
                co.WSCALEDST] = words[index_wscale + 3]
            subflow.attr[
                co.TYPE] = words[index_wscale + 4]
            index = words.index("sport")
            while index + 1 < len(words):
                attri = words[index]
                value = words[index + 1]
                # Cope with different format from tcptrace and mptcptrace
                if attri == co.SADDR or attri == co.DADDR:
                    value = co.long_ipv6_address(value)
                subflow.attr[attri] = value
                index += 2

            subflow.indicates_wifi_or_cell()
            connections[current_connection].flows[sub_flow_id] = subflow

            connections[current_connection].attr[co.S2D][co.BYTES] = {}
            connections[current_connection].attr[co.D2S][co.BYTES] = {}

        # Case 3: skip the line (no more current connection)
        else:
            current_connection = False
    return connections

##################################################
##        CONNECTION IDENTIFIER RELATED         ##
##################################################


def get_connection_id(csv_fname):
    """ Given the filename of the csv file, return the id of the MPTCP connection
        The id (returned as str) is assumed to be between last _ and last . in csv_fname
    """
    last_underscore_index = csv_fname.rindex("_")
    last_dot_index = csv_fname.rindex(".")
    return csv_fname[last_underscore_index + 1:last_dot_index]


def is_reverse_connection(csv_fname):
    """ Given the filename of the csv file, return True is it is a c2s flow or False if it is a s2c
        one
        The type is assumed to be before the first _ in csv_fname
    """
    first_underscore_index = csv_fname.index("_")
    return (csv_fname[0:first_underscore_index] == "s2c")


##################################################
##                  MPTCPTRACE                  ##
##################################################


def process_mptcptrace_cmd(cmd, pcap_filepath):
    """ Launch the command cmd given in argument, and return a dictionary containing information
        about connections of the pcap file analyzed
        Raise a MPTCPTraceError if mptcptrace encounters problems
    """
    pcap_flow_data_path = pcap_filepath[:-5] + '.out'
    flow_data_file = open(pcap_flow_data_path, 'w+')
    if subprocess.call(cmd, stdout=flow_data_file) != 0:
        raise MPTCPTraceError("Error of mptcptrace with " + pcap_filepath)

    connections = extract_flow_data(flow_data_file)
    # Don't forget to close and remove pcap_flow_data
    flow_data_file.close()
    os.remove(pcap_flow_data_path)
    return connections


##################################################
##                GRAPH RELATED                 ##
##################################################


def interesting_graph(csv_fname, connections):
    """ Return True if the MPTCP graph is worthy, else False
        This function assumes that a graph is interesting if it has at least one connection that
        if not 127.0.0.1 -> 127.0.0.1
        Note that is the graph is interesting and IPv4, indicates if the traffic is Wi-Fi or cell
    """
    connection_id = get_connection_id(csv_fname)
    for sub_flow_id, conn in connections[connection_id].flows.iteritems():
        # Only had the case for IPv4, but what is its equivalent in IPv6?
        if not conn.attr[co.TYPE] == co.IPv4:
            return True
        if not (conn.attr[co.SADDR] == co.LOCALHOST_IPv4 and conn.attr[co.DADDR] == co.LOCALHOST_IPv4):
            return True
    return False


def get_begin_values(datasets):
    """ Given an array with the content of a xpl file, return the first values of time and seq """
    for line in datasets:
        split_line = line.split(' ')
        if split_line[0] in co.XPL_ONE_POINT or split_line[0] in co.XPL_TWO_POINTS:
            return float(split_line[1]), int(split_line[2])

    return None, None


def get_begin_values_from_xpl(xpl_filepath):
    """ Given the path of the xpl file, return the first values of time and seq; don't need to open whole file """
    xpl_file = open(xpl_filepath)
    time = None
    seq = None
    line = xpl_file.readline()
    while line:
        split_line = line.split(' ')
        if split_line[0] in co.XPL_ONE_POINT or split_line[0] in co.XPL_TWO_POINTS:
            time = float(split_line[1])
            seq = int(split_line[2])
            line = False
        else:
            line = xpl_file.readline()

    return time, seq


def process_csv(csv_fname, connections, conn_id, is_reversed, count=0):
    """ Process the csv given in argument and after delete the file """
    try:
        csv_file = open(csv_fname)
        data = csv_file.readlines()
        csv_file.close()
    except IOError as e:
        print(str(e), file=sys.stderr)
        print('IOError for ' + csv_fname + ': no data extracted from csv', file=sys.stderr)
        if count < 10:
            process_csv(csv_fname, connections, conn_id, is_reversed, count=count+1)
        return

    reinject_offsets = {}
    reinject_nb = {}
    reinject_ts = {}
    reinject = {}
    bursts = []
    current_flow = -1
    first_seq_burst_on_flow = 0
    last_seq_burst_on_flow = 0
    begin_time_burst_on_flow = 0.0
    last_time_burst_on_flow = 0.0
    for i in range(0, len(connections[conn_id].flows)):
        reinject[i] = {}
        reinject_offsets[i] = 0
        reinject_nb[i] = 0
        reinject_ts[i] = []

    for line in data:
        split_line = line.split(',')
        if len(split_line) < 6:
            continue

        if int(split_line[3]) == 1:
            # Map
            if not int(split_line[2]) - 1 == current_flow and current_flow >= 0:
                # Save current burst (no way if start of connection)
                total_seq = last_seq_burst_on_flow - first_seq_burst_on_flow
                duration = last_time_burst_on_flow - begin_time_burst_on_flow
                bursts.append((current_flow, total_seq, duration, begin_time_burst_on_flow))

            if not int(split_line[2]) - 1 == current_flow:
                # Prepare for the next burst
                current_flow = int(split_line[2]) - 1
                first_seq_burst_on_flow = int(split_line[1])
                begin_time_burst_on_flow = float(split_line[0])

            last_seq_burst_on_flow = int(split_line[4])
            last_time_burst_on_flow = float(split_line[0])

        if int(split_line[3]) == 1 and (not int(split_line[5]) == -1):
            # Map and reinjected
            # Secucrity
            if int(split_line[5]) - 1 not in reinject_offsets:
                continue
            reinject_offsets[int(split_line[5]) - 1] += int(split_line[4]) - int(split_line[1])
            reinject_nb[int(split_line[5]) - 1] += 1
            reinject_ts[int(split_line[5]) - 1].append(float(split_line[0]))
            packet_seqs = (int(split_line[4]), int(split_line[1]))
            if packet_seqs not in reinject[int(split_line[5]) - 1]:
                reinject[int(split_line[5]) - 1][packet_seqs] = 1
            else:
                reinject[int(split_line[5]) - 1][packet_seqs] += 1
                print("WARNING: reinjection " + str(reinject[int(split_line[5]) - 1][packet_seqs]) + " for " + csv_fname)

    # Don't forget to consider the last burst
    if current_flow >= 0:
        total_seq = last_seq_burst_on_flow - first_seq_burst_on_flow
        duration = last_time_burst_on_flow - begin_time_burst_on_flow
        bursts.append((current_flow, total_seq, duration, begin_time_burst_on_flow))

    direction = co.D2S if is_reversed else co.S2D
    connections[conn_id].attr[direction][co.BURSTS] = bursts
    for i in range(0, len(connections[conn_id].flows)):
        connections[conn_id].flows[str(i)].attr[direction][co.REINJ_ORIG_PACKS] = reinject_nb[i]
        connections[conn_id].flows[str(i)].attr[direction][co.REINJ_ORIG_BYTES] = reinject_offsets[i]
        connections[conn_id].flows[str(i)].attr[direction][co.REINJ_ORIG_TIMESTAMP] = reinject_ts[i]
        connections[conn_id].flows[str(i)].attr[direction][co.REINJ_ORIG] = reinject[i]


def process_rtt_csv(csv_fname, rtt_all, connections, conn_id, is_reversed):
    """ Process the csv with rtt given in argument """
    try:
        csv_file = open(csv_fname)
        data = csv_file.readlines()
        csv_file.close()
    except IOError:
        print('IOError for ' + csv_fname + ': no data extracted from csv', file=sys.stderr)
        return

    rtt_data = []

    for line in data:
        split_line = line.split(',')
        # All data is good
        rtt_data.append(float(split_line[1]))

    direction = co.D2S if is_reversed else co.S2D
    connections[conn_id].attr[direction][co.RTT_SAMPLES] = len(rtt_data)
    if not rtt_data:
        return
    connections[conn_id].attr[direction][co.RTT_MIN] = np.min(rtt_data)
    connections[conn_id].attr[direction][co.RTT_MAX] = np.max(rtt_data)
    connections[conn_id].attr[direction][co.RTT_AVG] = np.mean(rtt_data)
    connections[conn_id].attr[direction][co.RTT_STDEV] = np.std(rtt_data)
    rtt_all[direction][conn_id] = rtt_data
    np_rtts = np.array(rtt_data)
    # Those are stored in the MPTCP connection itself because app delay at MPTCP level (not at its flows)
    connections[conn_id].attr[direction][co.RTT_99P] = np.percentile(np_rtts, 99)
    connections[conn_id].attr[direction][co.RTT_98P] = np.percentile(np_rtts, 98)
    connections[conn_id].attr[direction][co.RTT_97P] = np.percentile(np_rtts, 97)
    connections[conn_id].attr[direction][co.RTT_95P] = np.percentile(np_rtts, 95)
    connections[conn_id].attr[direction][co.RTT_90P] = np.percentile(np_rtts, 90)
    connections[conn_id].attr[direction][co.RTT_75P] = np.percentile(np_rtts, 75)
    connections[conn_id].attr[direction][co.RTT_MED] = np.percentile(np_rtts, 50)
    connections[conn_id].attr[direction][co.RTT_25P] = np.percentile(np_rtts, 25)


def generate_title(xpl_fname, connections):
    """ Generate the title for a mptcp connection """

    connection_id = get_connection_id(xpl_fname)
    title = "flows:" + str(len(connections[connection_id].flows)) + " "

    # If not reverse, correct order, otherwise reverse src and dst
    reverse = is_reverse_connection(xpl_fname)

    # Show all details of the subflows
    for sub_flow_id, conn in connections[connection_id].flows.iteritems():
        # Cannot have linebreak in xplot
        title += ' ' + "sf: " + sub_flow_id + " "
        if reverse:
            title += "(" + conn.attr[co.WSCALEDST] + " " + conn.attr[co.WSCALESRC] + ") "
            title += conn.attr[co.DADDR] + ":" + conn.attr[co.DPORT] + \
                " -> " + conn.attr[co.SADDR] + ":" + conn.attr[co.SPORT]
        else:
            title += "(" + conn.attr[co.WSCALESRC] + " " + conn.attr[co.WSCALEDST] + ") "
            title += conn.attr[co.SADDR] + ":" + conn.attr[co.SPORT] + \
                " -> " + conn.attr[co.DADDR] + ":" + conn.attr[co.DPORT]
        if co.IF in conn.attr:
            title += " [" + conn.attr[co.IF] + "]"
    return title


def rewrite_xpl(xpl_fname, xpl_data, begin_time, begin_seq, connections, conn_id, is_reversed):
    """ Rewrite the xpl file with filename xpl_fname in order to have the same relative time
        Number 1 is wifi (green), number 2 is cell (red)
    """
    rewrite_interface = True
    if len(connections[conn_id].flows) > 2:
        print("WARNING: too much flows, xpl plot will not follow (green = wifi, red = cellular)", file=sys.stderr)
        rewrite_interface = False

    is_title = False
    xpl_file = open(xpl_fname, 'w')

    # Time rewriting could have bug because of the float in Python
    for line in xpl_data:
        split_line = line.split(' ')

        if co.is_number(split_line[0]):
            if rewrite_interface:
                interface = connections[conn_id].flows[str(int(split_line[0]) - 1)].attr[co.IF]
                number = 1 if interface == co.WIFI else 2 if interface == co.CELL else 3
                xpl_file.write(str(number) + "\n")
            else:
                xpl_file.write(split_line[0])

        elif split_line[0] in co.XPL_ONE_POINT:
            # time = float(split_line[1]) - begin_time
            seq = int(split_line[2]) - begin_seq
            xpl_file.write(split_line[0] + " " + split_line[1] + " " + str(seq) + "\n")

        elif split_line[0] in co.XPL_TWO_POINTS:
            # Map
            # time_1 = float(split_line[1]) - begin_time
            seq_1 = int(split_line[2]) - begin_seq
            # time_2 = float(split_line[3]) - begin_time
            seq_2 = int(split_line[4]) - begin_seq

            xpl_file.write(split_line[0] + " " + split_line[1] + " " + str(seq_1) +
                           " " + split_line[3] + " " + str(seq_2) + "\n")

        elif is_title:
            is_title = False
            xpl_file.write(generate_title(xpl_fname, connections) + "\n")

        elif 'title' in split_line[0]:
            is_title = True
            xpl_file.write(line)

        else:
            xpl_file.write(line)

    xpl_file.close()


##################################################
##                    CHECKS                    ##
##################################################


def check_mptcp_joins(pcap_fullpath, print_out=sys.stdout):
    """ Check if the pcap given in argument has mp joins in a SYN->SYN/ACK->ACK fashion (only for both scenarios) """
    if 'rmnet' in os.path.basename(pcap_fullpath) or 'wlan' in os.path.basename(pcap_fullpath):
        return True
    mp_joins_fname = os.path.basename(pcap_fullpath[:-5]) + "_joins"
    mp_joins_file = open(mp_joins_fname, 'w')
    cmd = ['tshark', '-nr', pcap_fullpath, '-Y', 'tcp.options.mptcp.subtype==1']
    if subprocess.call(cmd, stdout=mp_joins_file) != 0:
        raise co.TSharkError("Error with tshark mptcp join " + pcap_fullpath)
    mp_joins_file.close()
    mp_joins_file = open(mp_joins_fname)
    mp_joins_data = mp_joins_file.readlines()
    mp_joins_file.close()

    os.remove(mp_joins_fname)

    mp_joins = {}

    for line in mp_joins_data:
        split_line = line.split(' ')
        if len(split_line) < 12:
            continue
        flags = line[line.rindex("[") + 1:line.rindex("]")]
        ports = split_line[7].split('\xe2\x86\x92')
        if len(ports) < 2:
            print("WARNING: not enough ports...", file=sys.stderr)
            return True
        sport = ports[0]
        dport = ports[1]
        if flags == 'SYN':
            mp_joins[(sport, dport)] = 1
        elif flags == 'SYN, ACK' and mp_joins.get((dport, sport), 0) == 1:
            mp_joins[(dport, sport)] = 2
        elif flags == 'ACK' and mp_joins.get((sport, dport), 0) == 2:
            return True

    return False


##################################################
##               MPTCP PROCESSING               ##
##################################################


def process_stats_csv(csv_fname, connections, count=0):
    """ Add information in connections based on the stats csv file, and remove it """
    try:
        csv_file = open(csv_fname)
        conn_id = get_connection_id(csv_fname)  # Or reuse conn_id from the stats file
        data = csv_file.readlines()
        first_seqs = None
        last_acks = None
        con_time = None
        begin_time = None
        for line in data:
            if 'firstSeq' in line:
                first_seqs = line.split(';')[-2:]
            elif 'lastAck' in line:
                last_acks = line.split(';')[-2:]
            elif 'conTime' in line:
                # Only takes one of the values, because they are the same
                con_time = line.split(';')[-2]
            elif 'beginTime' in line:
                # Only takes one of the values, because they are the same
                begin_time = line.split(';')[-2]

        if first_seqs and last_acks:
            # Notice that these values remove the reinjected bytes
            connections[conn_id].attr[co.S2D][co.BYTES_MPTCPTRACE] = int(last_acks[1]) - int(first_seqs[0])
            connections[conn_id].attr[co.D2S][co.BYTES_MPTCPTRACE] = int(last_acks[0]) - int(first_seqs[1])
        else:
            connections[conn_id].attr[co.S2D][co.BYTES_MPTCPTRACE] = 0
            connections[conn_id].attr[co.D2S][co.BYTES_MPTCPTRACE] = 0
        if con_time:
            connections[conn_id].attr[co.DURATION] = float(con_time)
        else:
            connections[conn_id].attr[co.DURATION] = 0.0
        if begin_time:
            connections[conn_id].attr[co.START] = float(begin_time)
        else:
            connections[conn_id].attr[co.START] = 0.0

        csv_file.close()

        # Remove now stats files
        # os.remove(csv_fname)
    except IOError as e:
        print(str(e), file=sys.stderr)
        print('IOError for ' + csv_fname + ': skipped', file=sys.stderr)
        if count < 10:
            process_stats_csv(csv_fname, connections, count=count+1)
        return
    except ValueError:
        print('ValueError for ' + csv_fname + ': skipped', file=sys.stderr)
        return


def first_pass_on_seq_xpl(xpl_fname, relative_start):
    """ Return the smallest timestamp between the smallest one in csv_fname and relative_start"""
    minimum = relative_start
    try:
        xpl_file = open(xpl_fname)
        data = xpl_file.readlines()
        if not data == [] and len(data) > 1:
            try:
                begin_time, begin_seq = get_begin_values(data)
                if begin_time < relative_start and not begin_time == 0.0:
                    minimum = begin_time
            except ValueError:
                print('ValueError for ' + xpl_fname + ': keep old value', file=sys.stderr)

        xpl_file.close()
    except IOError:
        print('IOError for ' + xpl_fname + ': keep old value', file=sys.stderr)

    return minimum


def first_pass_on_files(connections):
    """ Do a first pass on files generated by mptcptrace in current directory, without modifying them
        This returns the relative start of all connections and modify connections to add information
        contained in the files
    """
    for csv_fname in glob.glob('*.csv'):
        if csv_fname.startswith(MPTCP_STATS_PREFIX):
            process_stats_csv(csv_fname, connections)

    # relative_start is not used, don't lose time on it
    # relative_start = float("inf")
    # for xpl_fname in glob.glob('*.xpl'):
    #     if MPTCP_SEQ_FNAME in xpl_fname and MPTCP_RTT_FNAME not in xpl_fname:
    #         relative_start = first_pass_on_seq_xpl(xpl_fname, relative_start)
    #
    # return relative_start
    return 0


def process_seq_xpl(xpl_fname, connections, relative_start, min_bytes):
    """ If the csv is interesting, rewrite it in another folder csv_graph_tmp_dir
    """
    try:
        conn_id = get_connection_id(xpl_fname)
        is_reversed = is_reverse_connection(xpl_fname)
        # xpl_file = open(xpl_fname)
        # data = xpl_file.readlines()
        # xpl_file.close()
        # Check if there is data in file (and not only one line of 0s)
        # if not data == [] and len(data) > 1:
        direction = co.D2S if is_reversed else co.S2D
        if connections[conn_id].attr[direction][co.BYTES_MPTCPTRACE] >= min_bytes:
            # Collect begin time and seq num to plot graph starting at 0
            try:
                # begin_time, begin_seq = get_begin_values_from_xpl(xpl_fname)
                csv_fname = xpl_fname[:-4] + '.csv'
                process_csv(csv_fname, connections, conn_id, is_reversed)
                # Don't rewrite xpl, take too much time
                # rewrite_xpl(xpl_fname, data, begin_time, begin_seq, connections, conn_id, is_reversed)
            except ValueError:
                print('ValueError for ' + csv_fname + ': skipped', file=sys.stderr)

        # Remove the csv file
        # os.remove(csv_fname)

    except IOError:
        print('IOError for ' + xpl_fname + ': skipped', file=sys.stderr)


def process_rtt_xpl(xpl_fname, rtt_all, connections, relative_start, min_bytes):
    """ If there is data, store it in connections and rewrite file """
    try:
        conn_id = get_connection_id(xpl_fname)
        is_reversed = is_reverse_connection(xpl_fname)
        # xpl_file = open(xpl_fname)
        # data = xpl_file.readlines()
        # xpl_file.close()
        # Check if there is data in file (and not only one line of 0s)
        # if not data == [] and len(data) > 1:
        direction = co.D2S if is_reversed else co.S2D
        if connections[conn_id].attr[direction][co.BYTES_MPTCPTRACE] >= min_bytes:
            # Collect begin time and seq num to plot graph starting at 0
            try:
                csv_fname = xpl_fname[:-4] + '.csv'
                process_rtt_csv(csv_fname, rtt_all, connections, conn_id, is_reversed)
            except ValueError:
                print('ValueError for ' + xpl_fname + ': skipped', file=sys.stderr)

    except IOError:
        print('IOError for ' + xpl_fname + ': skipped', file=sys.stderr)


def plot_congestion_graphs(pcap_filepath, graph_dir_exp, cwin_data_all):
    """ Given the cwin data of all connections, plot their congestion graph """
    cwin_graph_dir = os.path.join(graph_dir_exp, co.CWIN_DIR)

    formatting = ['b', 'r', 'g', 'p']

    for cwin_name, cwin_data in cwin_data_all.iteritems():
        base_graph_fname = cwin_name + '_cwin'

        for direction, data_if in cwin_data.iteritems():
            dir_abr = 'd2s' if direction == co.D2S else 's2d' if direction == co.S2D else '?'
            graph_fname = base_graph_fname + '_' + dir_abr
            graph_fname += '.pdf'
            graph_filepath = os.path.join(cwin_graph_dir, graph_fname)

            nb_curves = len(data_if)
            co.plot_line_graph(data_if.values(), data_if.keys(), formatting[
                               :nb_curves], "Time [s]", "Congestion window [Bytes]", "Congestion window",
                               graph_filepath, ymin=0)


def process_gput_csv(csv_fname, connections):
    """ Collect the goodput of a connection """
    conn_id = get_connection_id(csv_fname)
    is_reversed = is_reverse_connection(csv_fname)
    try:
        gput_file = open(csv_fname)
        data = gput_file.readlines()
        gput_file.close()

        gput_data = []
        for line in data:
            split_line = line.split(',')
            if split_line[2] == '3':
                # Because it's in MByte/s, make it comparable with tcptrace
                gput_data.append(float(split_line[1]) * 1000000)

        if len(gput_data) > 0:
            direction = co.D2S if is_reversed else co.S2D
            connections[conn_id].attr[direction][co.THGPT_MPTCPTRACE] = np.mean(gput_data)
    except IOError as e:
        print(e, file=sys.stderr)
        print("No throughput info for " + csv_fname, file=sys.stderr)


def collect_acksize_csv(csv_fname, acksize_dict):
    """ Collect the ack size at the MPTCP level """
    conn_id = get_connection_id(csv_fname)
    direction = co.D2S if is_reverse_connection(csv_fname) else co.S2D
    try:
        acksize_file = open(csv_fname)
        data = acksize_file.readlines()
        acksize_file.close()

        acksize_conn = {}

        for line in data:
            split_line = line.split(',')
            # Ack info is the second number (don't convert in int, not needed now)
            if split_line[1] not in acksize_dict:
                acksize_conn[split_line[1]] = 1
            else:
                acksize_conn[split_line[1]] += 1

        acksize_dict[direction][conn_id] = acksize_conn

    except IOError as e:
        print(e, file=sys.stderr)
        print("No acksize info for " + csv_fname, file=sys.stderr)


# We can't change dir per thread, we should use processes
def process_trace(pcap_filepath, graph_dir_exp, stat_dir_exp, aggl_dir_exp, rtt_dir_exp, rtt_subflow_dir_exp, failed_conns_dir_exp, acksize_dir_exp, acksize_tcp_dir_exp, plot_cwin, min_bytes=0, light=False):
    """ Process a mptcp pcap file and generate graphs of its subflows """
    # if not check_mptcp_joins(pcap_filepath):
    #     print("WARNING: no mptcp joins on " + pcap_filepath, file=sys.stderr)
    csv_tmp_dir = tempfile.mkdtemp(dir=os.getcwd())
    connections = None
    do_tcp_processing = False
    try:
        with co.cd(csv_tmp_dir):
            # If segmentation faults, remove the -S option
            cmd = ['mptcptrace', '-f', pcap_filepath, '-s', '-S', '-t', '5000', '-w', '0']
            if not light:
                cmd += ['-G', '250', '-r', '2', '-F', '3', '-a']
            connections = process_mptcptrace_cmd(cmd, pcap_filepath)

            # Useful to count the number of reinjected bytes
            cmd = ['mptcptrace', '-f', pcap_filepath, '-s', '-a', '-t', '5000', '-w', '2']
            if not light:
                cmd += ['-G', '250', '-r', '2', '-F', '3']
            devnull = open(os.devnull, 'w')
            if subprocess.call(cmd, stdout=devnull) != 0:
                raise MPTCPTraceError("Error of mptcptrace with " + pcap_filepath)
            devnull.close()

            cmd = ['mptcptrace', '-d', '.', '-r', '2', '-t', '5000', '-w', '2']
            if not light:
                cmd += ['-G', '250', '-r', '2', '-F', '3']
            devnull = open(os.devnull, 'w')
            if subprocess.call(cmd, stdout=devnull) != 0:
                raise MPTCPTraceError("Error of mptcptrace with " + pcap_filepath)
            devnull.close()

            # The mptcptrace call will generate .xpl files to cope with
            # First see all xpl files, to detect the relative 0 of all connections
            # Also, compute the duration and number of bytes of the MPTCP connection
            relative_start = first_pass_on_files(connections)
            rtt_all = {co.S2D: {}, co.D2S: {}}
            acksize_all = {co.S2D: {}, co.D2S: {}}

            # Then really process xpl files
            for xpl_fname in glob.glob(os.path.join(csv_tmp_dir, '*.xpl')):
                if not light and MPTCP_RTT_FNAME in xpl_fname:
                    process_rtt_xpl(xpl_fname, rtt_all, connections, relative_start, min_bytes)
                elif MPTCP_SEQ_FNAME in xpl_fname:
                    process_seq_xpl(xpl_fname, connections, relative_start, min_bytes)
                try:
                    directory = co.DEF_RTT_DIR if MPTCP_RTT_FNAME in xpl_fname else co.TSG_THGPT_DIR
                    shutil.move(xpl_fname, os.path.join(
                        graph_dir_exp, directory, os.path.basename(pcap_filepath[:-5]) + "_" + xpl_fname))
                except IOError as e:
                    print(str(e), file=sys.stderr)

            # And by default, save all csv files
            for csv_fname in glob.glob(os.path.join(csv_tmp_dir, '*.csv')):
                if not light:
                    if MPTCP_GPUT_FNAME in csv_fname:
                        process_gput_csv(csv_fname, connections)
                try:
                    if MPTCP_RTT_FNAME in csv_fname:
                        conn_id = get_connection_id(csv_fname)
                        is_reversed = is_reverse_connection(csv_fname)
                        process_rtt_csv(csv_fname, rtt_all, connections, conn_id, is_reversed)
                        os.remove(csv_fname)
                        # co.move_file(csv_fname, os.path.join(
                        #    graph_dir_exp, co.DEF_RTT_DIR, os.path.basename(pcap_filepath[:-5]) + "_" + csv_fname))
                    elif MPTCP_SEQ_FNAME in csv_fname:
                        co.move_file(csv_fname, os.path.join(
                            graph_dir_exp, co.TSG_THGPT_DIR, os.path.basename(pcap_filepath[:-5]) + "_" + csv_fname))
                    elif MPTCP_ACKSIZE_FNAME in csv_fname:
                        collect_acksize_csv(csv_fname, acksize_all)
                        os.remove(csv_fname)
                    else:
                        if not light:
                            co.move_file(csv_fname, os.path.join(
                                graph_dir_exp, co.TSG_THGPT_DIR, os.path.basename(pcap_filepath[:-5]) + "_" + csv_fname))
                        else:
                            os.remove(csv_fname)
                except IOError as e:
                    print(str(e), file=sys.stderr)

            do_tcp_processing = True

    except MPTCPTraceError as e:
        print(str(e) + "; skip mptcp process", file=sys.stderr)

    shutil.rmtree(csv_tmp_dir)

    # Create aggregated graphes and add per interface information on MPTCPConnection
    # This will save the mptcp connections
    if connections and do_tcp_processing:
        # Save a first version as backup here; should be removed when no problem anymore
        # co.save_data(pcap_filepath, stat_dir_exp, connections)
        cwin_data_all = tcp.process_trace(pcap_filepath, graph_dir_exp, stat_dir_exp, aggl_dir_exp, rtt_dir_exp, rtt_subflow_dir_exp, failed_conns_dir_exp, acksize_tcp_dir_exp, plot_cwin, mptcp_connections=connections, light=light)
        co.save_data(pcap_filepath, acksize_dir_exp, acksize_all)
        co.save_data(pcap_filepath, rtt_dir_exp, rtt_all)
        co.save_data(pcap_filepath, stat_dir_exp, connections)
        if plot_cwin:
            plot_congestion_graphs(pcap_filepath, graph_dir_exp, cwin_data_all)


def process_trace_directory(directory_path, graph_dir_exp, stat_dir_exp, aggl_dir_exp, rtt_dir_exp, rtt_subflow_dir_exp, failed_conns_dir_exp, acksize_dir_exp, acksize_tcp_dir_exp, plot_cwin, min_bytes=0, light=False):
    """ Process a mptcp pcap file and generate graphs of its subflows """
    # if not check_mptcp_joins(pcap_filepath):
    #     print("WARNING: no mptcp joins on " + pcap_filepath, file=sys.stderr)
    connections = None
    do_tcp_processing = False
    try:
        with co.cd(directory_path):
            # If segmentation faults, remove the -S option
            cmd = ['mptcptrace', '-d', '.', '-s', '-S', '-t', '5000', '-w', '0']
            if not light:
                cmd += ['-G', '250', '-r', '2', '-F', '3', '-a']
            # Compatibility hack
            connections = process_mptcptrace_cmd(cmd, directory_path + '.pcap')

            # Useful to count the number of reinjected bytes
            cmd = ['mptcptrace', '-d', '.', '-s', '-a', '-t', '5000', '-w', '2']
            if not light:
                cmd += ['-G', '250', '-r', '2', '-F', '3']
            devnull = open(os.devnull, 'w')
            if subprocess.call(cmd, stdout=devnull) != 0:
                raise MPTCPTraceError("Error of mptcptrace with " + directory_path)
            devnull.close()

            cmd = ['mptcptrace', '-d', '.', '-r', '2', '-t', '5000', '-w', '2']
            if not light:
                cmd += ['-G', '250', '-r', '2', '-F', '3']
            devnull = open(os.devnull, 'w')
            if subprocess.call(cmd, stdout=devnull) != 0:
                raise MPTCPTraceError("Error of mptcptrace with " + directory_path)
            devnull.close()

            # The mptcptrace call will generate .xpl files to cope with
            # First see all xpl files, to detect the relative 0 of all connections
            # Also, compute the duration and number of bytes of the MPTCP connection
            relative_start = first_pass_on_files(connections)
            rtt_all = {co.S2D: {}, co.D2S: {}}
            acksize_all = {co.S2D: {}, co.D2S: {}}

            # Then really process xpl files
            for xpl_fname in glob.glob('*.xpl'):
                if not light and MPTCP_RTT_FNAME in xpl_fname:
                    process_rtt_xpl(xpl_fname, rtt_all, connections, relative_start, min_bytes)
                elif MPTCP_SEQ_FNAME in xpl_fname:
                    process_seq_xpl(xpl_fname, connections, relative_start, min_bytes)
                try:
                    directory = co.DEF_RTT_DIR if MPTCP_RTT_FNAME in xpl_fname else co.TSG_THGPT_DIR
                    shutil.move(xpl_fname, os.path.join(
                        graph_dir_exp, directory, os.path.basename(directory_path) + "_" + xpl_fname))
                except IOError as e:
                    print(str(e), file=sys.stderr)

            # And by default, save all csv files
            for csv_fname in glob.glob('*.csv'):
                if not light:
                    if MPTCP_GPUT_FNAME in csv_fname:
                        process_gput_csv(csv_fname, connections)
                try:
                    if MPTCP_RTT_FNAME in csv_fname:
                        conn_id = get_connection_id(csv_fname)
                        is_reversed = is_reverse_connection(csv_fname)
                        process_rtt_csv(csv_fname, rtt_all, connections, conn_id, is_reversed)
                        os.remove(csv_fname)
                    elif MPTCP_SEQ_FNAME in csv_fname:
                        co.move_file(csv_fname, os.path.join(
                            graph_dir_exp, co.TSG_THGPT_DIR, os.path.basename(directory_path) + "_" + csv_fname))
                    elif MPTCP_ACKSIZE_FNAME in csv_fname:
                        collect_acksize_csv(csv_fname, acksize_all)
                        os.remove(csv_fname)
                    else:
                        if not light:
                            co.move_file(csv_fname, os.path.join(
                                graph_dir_exp, co.TSG_THGPT_DIR, os.path.basename(directory_path) + "_" + csv_fname))
                        else:
                            os.remove(csv_fname)
                except IOError as e:
                    print(str(e), file=sys.stderr)

            do_tcp_processing = True

    except MPTCPTraceError as e:
        print(str(e) + "; skip mptcp process", file=sys.stderr)

    # Create aggregated graphes and add per interface information on MPTCPConnection
    # This will save the mptcp connections
    if connections and do_tcp_processing:
        # Save a first version as backup here; should be removed when no problem anymore
        # co.save_data(pcap_filepath, stat_dir_exp, connections)
        cwin_data_all = tcp.process_trace_directory(directory_path, graph_dir_exp, stat_dir_exp, aggl_dir_exp, rtt_dir_exp, rtt_subflow_dir_exp, failed_conns_dir_exp, acksize_tcp_dir_exp, plot_cwin, mptcp_connections=connections, light=light)
        co.save_data(directory_path + '.pcap', acksize_dir_exp, acksize_all)
        co.save_data(directory_path + '.pcap', rtt_dir_exp, rtt_all)
        co.save_data(directory_path + '.pcap', stat_dir_exp, connections)
        if plot_cwin:
            plot_congestion_graphs(directory_path + '.pcap', graph_dir_exp, cwin_data_all)
