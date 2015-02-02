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
import Gnuplot
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


class MPTCPTraceException(Exception):
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


def process_mptcptrace_cmd(cmd, pcap_fname):
    """ Launch the command cmd given in argument, and return a dictionary containing information
        about connections of the pcap file analyzed
    """
    pcap_flow_data = pcap_fname[:-5] + '.out'
    flow_data_file = open(pcap_flow_data, 'w+')
    if subprocess.call(cmd, stdout=flow_data_file) != 0:
        print("Error of mptcptrace with " + pcap_fname + "; skip process", file=sys.stderr)
        raise MPTCPTraceException()

    connections = extract_flow_data(flow_data_file)
    # Don't forget to close and remove pcap_flow_data
    flow_data_file.close()
    os.remove(pcap_flow_data)
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


def get_begin_values(first_line):
    split_line = first_line.split(',')
    return float(split_line[0]), int(split_line[1])


def write_graph_csv(csv_graph_tmp_dir, csv_fname, data, begin_time, begin_seq):
    """ Write in the graphs directory a new csv file containing relative values
        for plotting them
        Exit the program if an IOError is raised
    """
    try:
        graph_fname = os.path.join(csv_graph_tmp_dir, csv_fname)
        graph_file = open(graph_fname, 'w')
        # Modify lines for that
        for line in data:
            split_line = line.split(',')
            time = float(split_line[0]) - begin_time
            seq = int(split_line[1]) - begin_seq
            graph_file.write(str(time) + ',' + str(seq) + '\n')
        graph_file.close()
    except IOError:
        print('IOError for graph file with ' + csv_fname + ': stop', file=sys.stderr)
        exit(1)


def generate_title(csv_fname, connections):
    """ Generate the title for a mptcp connection """

    connection_id = get_connection_id(csv_fname)
    title = "flows:" + str(len(connections[connection_id].flows)) + " "

    # If not reverse, correct order, otherwise reverse src and dst
    reverse = is_reverse_connection(csv_fname)

    # Show all details of the subflows
    for sub_flow_id, conn in connections[connection_id].flows.iteritems():
        # \n must be interpreted as a raw type to works with GnuPlot.py
        title += r'\n' + "sf: " + sub_flow_id + " "
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


def create_graph_csv(pcap_fname, csv_fname, graph_dir_exp, connections):
    """ Generate pdf for the csv file of the pcap file
    """
    # First see if useful to show the graph
    if not interesting_graph(csv_fname, connections):
        return
    try:
        csv_file = open(csv_fname)
        data = csv_file.readlines()
    except IOError:
        print('IOError for ' + csv_fname + ': skipped', file=sys.stderr)
        return

    # If file was generated, the csv is not empty
    data_split = map(lambda x: x.split(','), data)
    data_plot = map(lambda x: map(lambda y: float(y), x), data_split)

    g = Gnuplot.Gnuplot(debug=0)
    g('set title "' + generate_title(csv_fname, connections) + '"')
    g('set style data linespoints')
    g.xlabel('Time [s]')
    g.ylabel('Sequence number')
    g.plot(data_plot)
    pdf_fname = os.path.join(graph_dir_exp,
                             os.path.basename(pcap_fname)[:-5] + "_" + csv_fname[:-4] + '.pdf')
    g.hardcopy(filename=pdf_fname, terminal='pdf')
    g.reset()


##################################################
##               MPTCP PROCESSING               ##
##################################################


# We can't change dir per thread, we should use processes
def process_trace(pcap_fname, graph_dir_exp, stat_dir_exp, min_bytes=0):
    """ Process a mptcp pcap file and generate graphs of its subflows """
    csv_tmp_dir = tempfile.mkdtemp(dir=os.getcwd())
    connections = None
    try:
        with co.cd(csv_tmp_dir):
            # If segmentation faults, remove the -S option
            cmd = ['mptcptrace', '-f', pcap_fname, '-s', '-S', '-w', '2']
            connections = process_mptcptrace_cmd(cmd, pcap_fname)

            csv_graph_tmp_dir = tempfile.mkdtemp(dir=graph_dir_exp)
            # The mptcptrace call will generate .csv files to cope with

            # First see all csv files, to detect the relative 0 of all connections
            # Also, compute the duration and number of bytes of the MPTCP connection
            relative_start = float("inf")
            for csv_fname in glob.glob('*.csv'):
                if csv_fname.startswith(MPTCP_STATS_PREFIX):
                    try:
                        csv_file = open(csv_fname)
                        # Or reuse conn_id from the stats file
                        conn_id = get_connection_id(csv_fname)
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
                            connections[conn_id].attr[co.BYTES_S2D] = int(last_acks[1]) - int(first_seqs[0])
                            connections[conn_id].attr[co.BYTES_D2S] = int(last_acks[0]) - int(first_seqs[1])
                        if con_time:
                            connections[conn_id].attr[co.DURATION] = float(con_time)


                        csv_file.close()
                        # Remove now stats files
                        os.remove(csv_fname)
                    except IOError:
                        print('IOError for ' + csv_fname + ': skipped', file=sys.stderr)
                        continue
                    except ValueError:
                        print('ValueError for ' + csv_fname + ': skipped', file=sys.stderr)
                        continue

                elif MPTCP_SEQ_FNAME in csv_fname:
                    try:
                        csv_file = open(csv_fname)
                        data = csv_file.readlines()
                        if not data == [] and len(data) > 1:
                            begin_time, begin_seq = get_begin_values(data[0])
                            if begin_time < relative_start and not begin_time == 0.0:
                                relative_start = begin_time
                        csv_file.close()
                    except IOError:
                        print('IOError for ' + csv_fname + ': skipped', file=sys.stderr)
                        continue
                    except ValueError:
                        print('ValueError for ' + csv_fname + ': skipped', file=sys.stderr)
                        continue

            # Then really process csv files
            for csv_fname in glob.glob('*.csv'):
                if MPTCP_SEQ_FNAME in csv_fname:
                    try:
                        conn_id = get_connection_id(csv_fname)
                        is_reversed = is_reverse_connection(csv_fname)
                        csv_file = open(csv_fname)
                        data = csv_file.readlines()
                        # Check if there is data in file (and not only one line of 0s)
                        if not data == [] and len(data) > 1:
                            if ((is_reversed and connections[conn_id].attr[co.BYTES_D2S] >= min_bytes) or
                                (not is_reversed and connections[conn_id].attr[co.BYTES_S2D] >= min_bytes)):
                                # Collect begin time and seq num to plot graph starting at 0
                                begin_time, begin_seq = get_begin_values(data[0])
                                write_graph_csv(csv_graph_tmp_dir, csv_fname, data, relative_start, begin_seq)

                        csv_file.close()
                        # Remove the csv file
                        os.remove(csv_fname)

                    except IOError:
                        print('IOError for ' + csv_fname + ': skipped', file=sys.stderr)
                        continue
                    except ValueError:
                        print('ValueError for ' + csv_fname + ': skipped', file=sys.stderr)
                        continue

            with co.cd(csv_graph_tmp_dir):
                for csv_fname in glob.glob('*.csv'):
                    # No point to plot information on subflows (as many points as there are subflows)
                    if MPTCP_SF_FNAME not in csv_fname:
                        create_graph_csv(pcap_fname, csv_fname, graph_dir_exp, connections)
                    # Remove the csv file
                    os.remove(csv_fname)

            # Remove temp dirs
            shutil.rmtree(csv_graph_tmp_dir)
    except MPTCPTraceException:
        print("Skip mptcp process", file=sys.stderr)

    shutil.rmtree(csv_tmp_dir)

    # Create aggregated graphes and add per interface information on MPTCPConnection
    # This will save the mptcp connections
    if connections:
        tcp.process_trace(pcap_fname, graph_dir_exp, stat_dir_exp, mptcp_connections=connections)
