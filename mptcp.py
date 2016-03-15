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
#  Contains code related to the processing of the outputs of mptcptrace

from __future__ import print_function

##################################################
#                    IMPORTS                     #
##################################################

from datetime import timedelta

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
#                   CONSTANTS                    #
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
# mptcptrace file identifier in csv filename for addaddr information
MPTCP_ADDADDR_FNAME = 'add_addr_'
# mptcptrace file identifier in csv filename for rmaddr information
MPTCP_RMADDR_FNAME = 'rm_addr_'


##################################################
#                   EXCEPTIONS                   #
##################################################


class MPTCPTraceError(Exception):
    pass

##################################################
#            CONNECTION DATA RELATED             #
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


def convert_MPTCPConnections_to_dict(mptcp_connections):
    mptcp_dict = {}
    for key in mptcp_connections:
        mptcp_dict[key] = vars(mptcp_connections[key])
        # If we want a full dict, we need to convert the MPTCPSubFlows to dict total_seconds
        for mptcp_subflow_key in mptcp_connections[key]["flows"]:
            mptcp_dict[key]["flows"][mptcp_subflow_key] = vars(mptcp_connections[key]["flows"][mptcp_subflow_key])

    return mptcp_dict


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
            current_connection = int(words[-1])
            connections[current_connection] = MPTCPConnection(current_connection)

        # Case 2: line for a subflow
        elif current_connection is not False and line.startswith("\tSubflow"):
            # A typical line:
            #   Subflow 0 with wscale : 6 0 IPv4 sport 59570 dport 443 saddr
            # 37.185.171.74 daddr 194.78.99.114
            words = line.split()
            sub_flow_id = int(words[1])
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

            connections[current_connection].attr[co.C2S][co.BYTES] = {}
            connections[current_connection].attr[co.S2C][co.BYTES] = {}

            connections[current_connection].attr[co.C2S][co.RETRANS_DSS] = []
            connections[current_connection].attr[co.S2C][co.RETRANS_DSS] = []

        # Case 3: skip the line (no more current connection)
        else:
            current_connection = False
    return connections

##################################################
#         CONNECTION IDENTIFIER RELATED          #
##################################################


def get_connection_id(csv_fname):
    """ Given the filename of the csv file, return the id of the MPTCP connection
        The id (returned as int) is assumed to be between last _ and last . in csv_fname
    """
    last_underscore_index = csv_fname.rindex("_")
    last_dot_index = csv_fname.rindex(".")
    return int(csv_fname[last_underscore_index + 1:last_dot_index])


def is_reverse_connection(csv_fname):
    """ Given the filename of the csv file, return True is it is a c2s flow or False if it is a s2c
        one
        The type is assumed to be before the first _ in csv_fname
    """
    first_underscore_index = csv_fname.index("_")
    return (csv_fname[0:first_underscore_index] == "s2c")


##################################################
#                   MPTCPTRACE                   #
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
#                 GRAPH RELATED                  #
##################################################


def process_csv(csv_fname, connections, conn_id, is_reversed):
    """ Process the csv given in argument """
    if conn_id not in connections:
        # Not a real connection; skip it
        return

    try:
        csv_file = open(csv_fname)
        data = csv_file.readlines()
        csv_file.close()
    except IOError as e:
        print(str(e), file=sys.stderr)
        print('IOError for ' + csv_fname + ': no data extracted from csv', file=sys.stderr)
        return

    reinject_offsets = {}
    reinject_nb = {}
    reinject_ts = {}
    reinject = {}
    is_reinjection = {}
    bursts = []
    current_flow = -1
    count_seq_burst = 0
    count_pkt_burst = 0
    begin_time_burst_on_flow = 0.0
    last_time_burst_on_flow = 0.0
    for i in range(0, len(connections[conn_id].flows)):
        reinject[i] = {}
        is_reinjection[i] = {}
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
                duration = last_time_burst_on_flow - begin_time_burst_on_flow
                bursts.append((current_flow, count_seq_burst, count_pkt_burst, duration, begin_time_burst_on_flow))

            if not int(split_line[2]) - 1 == current_flow:
                # Prepare for the next burst
                current_flow = int(split_line[2]) - 1
                count_seq_burst = 0
                count_pkt_burst = 0
                begin_time_burst_on_flow = float(split_line[0])

            count_seq_burst += (int(split_line[4]) - int(split_line[1])) % 2**32
            count_pkt_burst += 1
            last_time_burst_on_flow = float(split_line[0])

        if int(split_line[3]) == 1 and (not int(split_line[5]) == -1):
            # Map and reinjected
            # Security
            if int(split_line[5]) - 1 not in reinject_offsets:
                continue
            reinject_offsets[int(split_line[5]) - 1] += (int(split_line[4]) - int(split_line[1])) % 2**32
            is_reinjection[int(split_line[2]) - 1][split_line[0]] = (int(split_line[4]) - int(split_line[1])) % 2**32
            reinject_nb[int(split_line[5]) - 1] += 1
            reinject_ts[int(split_line[5]) - 1].append(float(split_line[0]))
            packet_seqs = (int(split_line[4]), int(split_line[1]))
            if packet_seqs not in reinject[int(split_line[5]) - 1]:
                reinject[int(split_line[5]) - 1][packet_seqs] = 1
            else:
                reinject[int(split_line[5]) - 1][packet_seqs] += 1
                # print("WARNING: reinjection " + str(reinject[int(split_line[5]) - 1][packet_seqs]) + " for " + csv_fname)

    # Don't forget to consider the last burst
    if current_flow >= 0:
        duration = last_time_burst_on_flow - begin_time_burst_on_flow
        bursts.append((current_flow, count_seq_burst, count_pkt_burst, duration, begin_time_burst_on_flow))

    direction = co.S2C if is_reversed else co.C2S
    connections[conn_id].attr[direction][co.BURSTS] = bursts
    for i in range(0, len(connections[conn_id].flows)):
        connections[conn_id].flows[i].attr[direction][co.REINJ_ORIG_PACKS] = reinject_nb[i]
        connections[conn_id].flows[i].attr[direction][co.REINJ_ORIG_BYTES] = reinject_offsets[i]
        connections[conn_id].flows[i].attr[direction][co.REINJ_ORIG_TIMESTAMP] = reinject_ts[i]
        connections[conn_id].flows[i].attr[direction][co.REINJ_ORIG] = reinject[i]
        connections[conn_id].flows[i].attr[direction][co.IS_REINJ] = is_reinjection[i]


def process_rtt_csv(csv_fname, rtt_all, connections, conn_id, is_reversed):
    """ Process the csv with rtt given in argument """
    if conn_id not in connections:
        print(conn_id, "not in connections", file=sys.stderr)
        return
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

    direction = co.S2C if is_reversed else co.C2S
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


##################################################
#                     CHECKS                     #
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
#                MPTCP PROCESSING                #
##################################################


def process_stats_csv(csv_fname, connections):
    """ Add information in connections based on the stats csv file """
    try:
        conn_id = get_connection_id(csv_fname)  # Or reuse conn_id from the stats file
        if conn_id not in connections:
            # Not a real connection; skip it
            return

        csv_file = open(csv_fname)
        data = csv_file.readlines()
        seq_acked = None
        con_time = None
        begin_time = None
        bytes_reinjected = None
        pc_reinjected = None
        for line in data:
            if 'seqAcked' in line:
                seq_acked = line.split(';')[-2:]
            elif 'conTime' in line:
                # Only takes one of the values, because they are the same
                con_time = line.split(';')[-2]
            elif 'beginTime' in line:
                # Only takes one of the values, because they are the same
                begin_time = line.split(';')[-2]
            elif 'bytesReinjected' in line:
                bytes_reinjected = line.split(';')[-2:]
            elif 'precentReinjected' in line:
                pc_reinjected = line.split(';')[-2:]

        if seq_acked:
            # Notice that these values remove the reinjected bytes
            if int(seq_acked[0]) == 4294967295:
                connections[conn_id].attr[co.C2S][co.BYTES_MPTCPTRACE] = 1
            else:
                connections[conn_id].attr[co.C2S][co.BYTES_MPTCPTRACE] = int(seq_acked[0])
            if int(seq_acked[1]) == 4294967295:
                connections[conn_id].attr[co.S2C][co.BYTES_MPTCPTRACE] = 1
            else:
                connections[conn_id].attr[co.S2C][co.BYTES_MPTCPTRACE] = int(seq_acked[1])
        else:
            connections[conn_id].attr[co.C2S][co.BYTES_MPTCPTRACE] = 0
            connections[conn_id].attr[co.S2C][co.BYTES_MPTCPTRACE] = 0
        if con_time:
            connections[conn_id].attr[co.DURATION] = float(con_time)
        else:
            connections[conn_id].attr[co.DURATION] = 0.0
        if begin_time:
            str_begin = begin_time.split('.')
            connections[conn_id].attr[co.START] = timedelta(seconds=int(str_begin[0]), microseconds=int(str_begin[1]))
        else:
            connections[conn_id].attr[co.START] = timedelta(0)
        if bytes_reinjected:
            connections[conn_id].attr[co.C2S][co.REINJ_BYTES] = int(bytes_reinjected[0])
            connections[conn_id].attr[co.S2C][co.REINJ_BYTES] = int(bytes_reinjected[1])
        else:
            connections[conn_id].attr[co.C2S][co.REINJ_BYTES] = 0
            connections[conn_id].attr[co.S2C][co.REINJ_BYTES] = 0
        if pc_reinjected:
            connections[conn_id].attr[co.C2S][co.REINJ_PC] = pc_reinjected[0]
            connections[conn_id].attr[co.S2C][co.REINJ_PC] = pc_reinjected[1]
        else:
            connections[conn_id].attr[co.C2S][co.REINJ_PC] = 0.0
            connections[conn_id].attr[co.S2C][co.REINJ_PC] = 0.0
        csv_file.close()

    except IOError as e:
        print(str(e), file=sys.stderr)
        print('IOError for ' + csv_fname + ': skipped', file=sys.stderr)
        return

    except ValueError:
        print('ValueError for ' + csv_fname + ': skipped', file=sys.stderr)
        return


def first_pass_on_files(connections):
    """ Do a first pass on files generated by mptcptrace in current directory, without modifying them
        This modifies connections to add information contained in the files
    """
    for csv_fname in glob.glob('*.csv'):
        if csv_fname.startswith(MPTCP_STATS_PREFIX):
            process_stats_csv(csv_fname, connections)


def process_gput_csv(csv_fname, connections):
    """ Collect the goodput of a connection """
    conn_id = get_connection_id(csv_fname)
    if conn_id not in connections:
        # Not a real connection: skip it
        return

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
            direction = co.S2C if is_reversed else co.C2S
            connections[conn_id].attr[direction][co.THGPT_MPTCPTRACE] = np.mean(gput_data)
    except IOError as e:
        print(e, file=sys.stderr)
        print("No throughput info for " + csv_fname, file=sys.stderr)


def collect_acksize_csv(csv_fname, connections, acksize_dict):
    """ Collect the ack size at the MPTCP level """
    conn_id = get_connection_id(csv_fname)
    if conn_id not in connections:
        # Not a real connection: skip it
        return

    direction = co.S2C if is_reverse_connection(csv_fname) else co.C2S
    try:
        acksize_file = open(csv_fname)
        data = acksize_file.readlines()
        acksize_file.close()

        acksize_conn = {}

        for line in data:
            split_line = line.split(',')
            # Ack info is the second number (convert in int for simpler processing)
            acked_bytes = int(split_line[1])
            if acked_bytes not in acksize_conn:
                acksize_conn[acked_bytes] = 1
            else:
                acksize_conn[acked_bytes] += 1

        acksize_dict[direction][conn_id] = acksize_conn

    except IOError as e:
        print(e, file=sys.stderr)
        print("No acksize info for " + csv_fname, file=sys.stderr)


def process_add_addr_csv(csv_fname, connections, conn_id):
    add_addrs = []
    csv_file = open(csv_fname)
    csv_data = csv_file.readlines()

    for line in csv_data:
        add_addrs.append(line.split(','))

    connections[conn_id].attr[co.ADD_ADDRS] = add_addrs
    csv_file.close()


def process_rm_addr_csv(csv_fname, connections, conn_id):
    rm_addrs = []
    csv_file = open(csv_fname)
    csv_data = csv_file.readlines()

    for line in csv_data:
        rm_addrs.append(line.split(','))

    connections[conn_id].attr[co.RM_ADDRS] = rm_addrs
    csv_file.close()


def process_trace(pcap_filepath, graph_dir_exp, stat_dir_exp, aggl_dir_exp, rtt_dir_exp, rtt_subflow_dir_exp, failed_conns_dir_exp, acksize_dir_exp, acksize_tcp_dir_exp, plot_cwin, tcpcsm, min_bytes=0, light=False, return_dict=False):
    """ Process a mptcp pcap file and generate graphs of its subflows
        Notice that we can't change dir per thread, we should use processes
    """
    # if not check_mptcp_joins(pcap_filepath):
    #     print("WARNING: no mptcp joins on " + pcap_filepath, file=sys.stderr)
    csv_tmp_dir = tempfile.mkdtemp(dir=os.getcwd())
    connections = None
    do_tcp_processing = False
    try:
        with co.cd(csv_tmp_dir):
            # If segmentation faults, remove the -S option
            # cmd = ['mptcptrace', '-f', pcap_filepath, '-s', '-S', '-t', '5000', '-w', '0']
            # if not light:
            #     cmd += ['-G', '250', '-r', '2', '-F', '3', '-a']
            # connections = process_mptcptrace_cmd(cmd, pcap_filepath)
            #
            # # Useful to count the number of reinjected bytes
            # cmd = ['mptcptrace', '-f', pcap_filepath, '-s', '-a', '-t', '5000', '-w', '2']
            # if not light:
            #     cmd += ['-G', '250', '-r', '2', '-F', '3']
            # devnull = open(os.devnull, 'w')
            # if subprocess.call(cmd, stdout=devnull) != 0:
            #     raise MPTCPTraceError("Error of mptcptrace with " + pcap_filepath)
            # devnull.close()
            #
            # cmd = ['mptcptrace', '-f', pcap_filepath, '-r', '2', '-t', '5000', '-w', '2']
            # if not light:
            #     cmd += ['-G', '250', '-r', '2', '-F', '3']
            # devnull = open(os.devnull, 'w')
            # if subprocess.call(cmd, stdout=devnull) != 0:
            #     raise MPTCPTraceError("Error of mptcptrace with " + pcap_filepath)
            # devnull.close()

            cmd = ['mptcptrace', '-f', pcap_filepath, '-s', '-S', '-a', '-A', '-R', '-r', '2', '-t', '5000', '-w', '2']
            connections = process_mptcptrace_cmd(cmd, pcap_filepath)

            # The mptcptrace call will generate .xpl files to cope with
            # First see all xpl files, to detect the relative 0 of all connections
            # Also, compute the duration and number of bytes of the MPTCP connection
            first_pass_on_files(connections)
            rtt_all = {co.C2S: {}, co.S2C: {}}
            acksize_all = {co.C2S: {}, co.S2C: {}}

            # Then really process xpl files
            if return_dict:
                for xpl_fname in glob.glob(os.path.join('*.xpl')):
                    try:
                        os.remove(xpl_fname)
                    except IOError as e:
                        print(str(e), file=sys.stderr)
            else:
                for xpl_fname in glob.glob(os.path.join('*.xpl')):
                    try:
                        directory = co.DEF_RTT_DIR if MPTCP_RTT_FNAME in xpl_fname else co.TSG_THGPT_DIR
                        shutil.move(xpl_fname, os.path.join(
                            graph_dir_exp, directory, os.path.basename(pcap_filepath[:-5]) + "_" + os.path.basename(xpl_fname)))
                    except IOError as e:
                        print(str(e), file=sys.stderr)

            # And by default, save only seq csv files
            for csv_fname in glob.glob(os.path.join('*.csv')):
                if not light:
                    if MPTCP_GPUT_FNAME in os.path.basename(csv_fname):
                        process_gput_csv(csv_fname, connections)
                try:
                    if os.path.basename(csv_fname).startswith(MPTCP_ADDADDR_FNAME):
                        conn_id = get_connection_id(os.path.basename(csv_fname))
                        if conn_id not in connections:
                            # Not a real connection; skip it
                            continue

                        process_add_addr_csv(csv_fname, connections, conn_id)
                        os.remove(csv_fname)

                    elif os.path.basename(csv_fname).startswith(MPTCP_RMADDR_FNAME):
                        conn_id = get_connection_id(os.path.basename(csv_fname))
                        if conn_id not in connections:
                            # Not a real connection; skip it
                            continue

                        process_rm_addr_csv(csv_fname, connections, conn_id)
                        os.remove(csv_fname)

                    elif MPTCP_RTT_FNAME in os.path.basename(csv_fname):
                        conn_id = get_connection_id(os.path.basename(csv_fname))
                        if conn_id not in connections:
                            # Not a real connection; skip it
                            continue

                        is_reversed = is_reverse_connection(os.path.basename(csv_fname))
                        process_rtt_csv(csv_fname, rtt_all, connections, conn_id, is_reversed)
                        os.remove(csv_fname)
                        # co.move_file(csv_fname, os.path.join(
                        #    graph_dir_exp, co.DEF_RTT_DIR, os.path.basename(pcap_filepath[:-5]) + "_" + csv_fname))
                    elif MPTCP_SEQ_FNAME in os.path.basename(csv_fname):
                        conn_id = get_connection_id(os.path.basename(csv_fname))
                        if conn_id not in connections:
                            # Not a real connection; skip it
                            continue

                        is_reversed = is_reverse_connection(os.path.basename(csv_fname))
                        process_csv(csv_fname, connections, conn_id, is_reversed)
                        if return_dict:
                            try:
                                os.remove(csv_fname)
                            except Exception:
                                pass
                        else:
                            co.move_file(csv_fname, os.path.join(
                                graph_dir_exp, co.TSG_THGPT_DIR, os.path.basename(pcap_filepath[:-5]) + "_" + os.path.basename(csv_fname)))
                    elif MPTCP_ACKSIZE_FNAME in os.path.basename(csv_fname):
                        collect_acksize_csv(csv_fname, connections, acksize_all)
                        os.remove(csv_fname)
                    else:
                        if not light and not return_dict:
                            co.move_file(csv_fname, os.path.join(
                                graph_dir_exp, co.TSG_THGPT_DIR, os.path.basename(pcap_filepath[:-5]) + "_" + os.path.basename(csv_fname)))
                        else:
                            os.remove(csv_fname)
                except IOError as e:
                    print(str(e), file=sys.stderr)

            do_tcp_processing = True

    except MPTCPTraceError as e:
        print(str(e) + "; skip mptcp process", file=sys.stderr)

    shutil.rmtree(csv_tmp_dir)

    # This will save the mptcp connections
    if connections and do_tcp_processing:
        dicts = tcp.process_trace(pcap_filepath, graph_dir_exp, stat_dir_exp, failed_conns_dir_exp, acksize_tcp_dir_exp, tcpcsm, mptcp_connections=connections, light=light, return_dict=return_dict)
        if return_dict:
            tcp_connections, acksize_all_tcp = dicts
            co.save_data(pcap_filepath, stat_dir_exp, convert_MPTCPConnections_to_dict(connections))
        else:
            co.save_data(pcap_filepath, acksize_dir_exp, acksize_all)
            co.save_data(pcap_filepath, rtt_dir_exp, rtt_all)
            co.save_data(pcap_filepath, stat_dir_exp, connections)
