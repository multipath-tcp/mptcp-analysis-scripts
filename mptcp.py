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
# mptcptrace stats files prefix in csv filename of a subflow
MPTCP_STATS_PREFIX = 'stats_'

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
                subflow.attr[attri] = value
                index += 2

            subflow.indicates_wifi_or_rmnet()
            connections[current_connection].flows[sub_flow_id] = subflow

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
        Note that is the graph is interesting and IPv4, indicates if the traffic is Wi-Fi or rmnet
    """
    connection_id = get_connection_id(csv_fname)
    for sub_flow_id, conn in connections[connection_id].flows.iteritems():
        # Only had the case for IPv4, but what is its equivalent in IPv6?
        if not conn.attr[co.TYPE] == 'IPv4':
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


def process_csv(csv_fname, connections, conn_id, is_reversed):
    """ Process the csv given in argument and after delete the file """
    try:
        csv_file = open(csv_fname)
        data = csv_file.readlines()
        csv_file.close()
    except IOError:
        print('IOError for ' + csv_fname + ': no data extracted from csv', file=sys.stderr)

    reinject_offsets = {0: 0, 1: 0, 2: 0, 3: 0}
    reinject_nb = {0: 0, 1: 0, 2: 0, 3: 0}

    for line in data:
        split_line = line.split(',')
        if int(split_line[3]) == 1 and (not int(split_line[5]) == -1):
            # Map and reinjected
            reinject_offsets[int(split_line[5]) - 1] += int(split_line[4]) - int(split_line[1])
            reinject_nb[int(split_line[5]) - 1] += 1

    for i in range(0, len(connections[conn_id].flows)):
        if is_reversed:
            connections[conn_id].flows[str(i)].attr[co.REINJ_ORIG_PACKS_D2S] = reinject_nb[i]
            connections[conn_id].flows[str(i)].attr[co.REINJ_ORIG_BYTES_D2S] = reinject_offsets[i]
        else:
            connections[conn_id].flows[str(i)].attr[co.REINJ_ORIG_PACKS_S2D] = reinject_nb[i]
            connections[conn_id].flows[str(i)].attr[co.REINJ_ORIG_BYTES_S2D] = reinject_offsets[i]


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
        Number 1 is wifi (green), number 2 is rmnet (red)
    """
    if len(connections[conn_id].flows) > 2:
        print("WARNING: xpl plot only show two curves (green = wifi, red = cellular)", file=sys.stderr)

    is_title = False
    xpl_file = open(xpl_fname, 'w')

    # Time rewriting could have bug because of the float in Python
    for line in xpl_data:
        split_line = line.split(' ')

        if co.is_number(split_line[0]):
            interface = connections[conn_id].flows[str(int(split_line[0]) - 1)].attr[co.IF]
            number = 1 if interface == co.WIFI else 2 if interface == co.RMNET else 3
            xpl_file.write(str(number) + "\n")

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
    if 'both' not in os.path.basename(pcap_fullpath):
        return True
    mp_joins_fname = os.path.basename(pcap_fullpath[:-5]) + "_joins"
    mp_joins_file = open(mp_joins_fname, 'w')
    cmd = ['tshark', '-r', pcap_fullpath, '-Y', 'tcp.options.mptcp.subtype==1']
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
        if split_line[10] == '[SYN]':
            mp_joins[(split_line[7], split_line[9])] = 1
        elif split_line[10] == '[SYN,' and split_line[11] == 'ACK]' and mp_joins.get((split_line[9], split_line[7]), 0) == 1:
            mp_joins[(split_line[9], split_line[7])] = 2
        elif split_line[10] == '[ACK]' and mp_joins.get((split_line[7], split_line[9]), 0) == 2:
            return True

    return False


##################################################
##               MPTCP PROCESSING               ##
##################################################


def process_stats_csv(csv_fname, connections):
    """ Add information in connections based on the stats csv file, and remove it """
    try:
        csv_file = open(csv_fname)
        conn_id = get_connection_id(csv_fname)  # Or reuse conn_id from the stats file
        data = csv_file.readlines()
        first_seqs = None
        last_acks = None
        con_time = None
        for line in data:
            if 'firstSeq' in line:
                first_seqs = line.split(';')[-2:]
            elif 'lastAck' in line:
                last_acks = line.split(';')[-2:]
            elif 'conTime' in line:
                # Only takes one of the values, because they are the same
                con_time = line.split(';')[-1]

        if first_seqs and last_acks:
            # Notice that these values remove the reinjected bytes
            connections[conn_id].attr[co.BYTES_S2D] = int(last_acks[1]) - int(first_seqs[0])
            connections[conn_id].attr[co.BYTES_D2S] = int(last_acks[0]) - int(first_seqs[1])
        if con_time:
            connections[conn_id].attr[co.DURATION] = float(con_time)

        csv_file.close()

        # Remove now stats files
        # os.remove(csv_fname)
    except IOError:
        print('IOError for ' + csv_fname + ': skipped', file=sys.stderr)
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

    relative_start = float("inf")
    for xpl_fname in glob.glob('*.xpl'):
        if MPTCP_SEQ_FNAME in xpl_fname:
            relative_start = first_pass_on_seq_xpl(xpl_fname, relative_start)

    return relative_start


def process_seq_xpl(xpl_fname, connections, relative_start, min_bytes):
    """ If the csv is interesting, rewrite it in another folder csv_graph_tmp_dir
    """
    try:
        conn_id = get_connection_id(xpl_fname)
        is_reversed = is_reverse_connection(xpl_fname)
        xpl_file = open(xpl_fname)
        data = xpl_file.readlines()
        xpl_file.close()
        # Check if there is data in file (and not only one line of 0s)
        if not data == [] and len(data) > 1:
            if ((is_reversed and connections[conn_id].attr[co.BYTES_D2S] >= min_bytes) or
                    (not is_reversed and connections[conn_id].attr[co.BYTES_S2D] >= min_bytes)):
                # Collect begin time and seq num to plot graph starting at 0
                try:
                    begin_time, begin_seq = get_begin_values(data)
                    csv_fname = xpl_fname[:-4] + '.csv'
                    process_csv(csv_fname, connections, conn_id, is_reversed)
                    rewrite_xpl(xpl_fname, data, begin_time, begin_seq, connections, conn_id, is_reversed)
                except ValueError:
                    print('ValueError for ' + csv_fname + ': skipped', file=sys.stderr)

        # Remove the csv file
        # os.remove(csv_fname)

    except IOError:
        print('IOError for ' + csv_fname + ': skipped', file=sys.stderr)


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


# We can't change dir per thread, we should use processes
def process_trace(pcap_filepath, graph_dir_exp, stat_dir_exp, aggl_dir_exp, plot_cwin, min_bytes=0):
    """ Process a mptcp pcap file and generate graphs of its subflows """
    if not check_mptcp_joins(pcap_filepath):
        print("WARNING: no mptcp joins on " + pcap_filepath, file=sys.stderr)
    csv_tmp_dir = tempfile.mkdtemp(dir=os.getcwd())
    connections = None
    try:
        with co.cd(csv_tmp_dir):
            # If segmentation faults, remove the -S option
            cmd = ['mptcptrace', '-f', pcap_filepath, '-s', '-S', '-G', '250',  '-w', '0']
            connections = process_mptcptrace_cmd(cmd, pcap_filepath)

            # Useful to count the number of reinjected bytes
            cmd = ['mptcptrace', '-f', pcap_filepath, '-s', '-G', '250', '-w', '2']
            devnull = open(os.devnull, 'w')
            if subprocess.call(cmd, stdout=devnull) != 0:
                raise MPTCPTraceError("Error of mptcptrace with " + pcap_filepath)
            devnull.close()

            # The mptcptrace call will generate .xpl files to cope with
            # First see all xpl files, to detect the relative 0 of all connections
            # Also, compute the duration and number of bytes of the MPTCP connection
            relative_start = first_pass_on_files(connections)

            # Then really process xpl files
            for xpl_fname in glob.glob('*.xpl'):
                if MPTCP_SEQ_FNAME in xpl_fname:
                    process_seq_xpl(xpl_fname, connections, relative_start, min_bytes)
                try:
                    co.move_file(xpl_fname, os.path.join(
                        graph_dir_exp, co.TSG_THGPT_DIR, os.path.basename(pcap_filepath[:-5]) + "_" + xpl_fname))
                except IOError as e:
                    print(str(e), file=sys.stderr)

            # And by default, save all csv files
            for csv_fname in glob.glob('*.csv'):
                try:
                    co.move_file(csv_fname, os.path.join(
                        graph_dir_exp, co.TSG_THGPT_DIR, os.path.basename(pcap_filepath[:-5]) + "_" + csv_fname))
                except IOError as e:
                    print(str(e), file=sys.stderr)

    except MPTCPTraceError as e:
        print(str(e) + "; skip mptcp process", file=sys.stderr)

    shutil.rmtree(csv_tmp_dir)

    # Create aggregated graphes and add per interface information on MPTCPConnection
    # This will save the mptcp connections
    if connections:
        cwin_data_all = tcp.process_trace(pcap_filepath, graph_dir_exp, stat_dir_exp, aggl_dir_exp, plot_cwin, mptcp_connections=connections)
        co.save_data(pcap_filepath, stat_dir_exp, connections)
        if plot_cwin:
            plot_congestion_graphs(pcap_filepath, graph_dir_exp, cwin_data_all)
