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
#  Contains code related to the processing of TCP traces

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

##################################################
##                  EXCEPTIONS                  ##
##################################################


class TCPTraceError(Exception):
    pass


class MergecapError(Exception):
    pass


class TCPRewriteError(Exception):
    pass

##################################################
##           CONNECTION DATA RELATED            ##
##################################################


class TCPConnection(co.BasicConnection):

    """ Represent a TCP connection """
    flow = None

    def __init__(self, conn_id):
        super(TCPConnection, self).__init__(conn_id)
        self.flow = co.BasicFlow()


def fix_tcptrace_time_bug(tcptrace_time):
    """ Given a string representing a time, correct the bug of TCPTrace (0 are skipped if just next to the dot)
        Return a string representing the correct time
    """
    [sec, usec] = tcptrace_time.split('.')
    if len(usec) < 6:
        for i in range(6 - len(usec)):
            usec = '0' + usec

    return sec + '.' + usec


def compute_duration(info):
    """ Given the output of tcptrace as an array, compute the duration of a tcp connection
        The computation done (in term of tcptrace's attributes) is last_packet - first_packet
    """
    first_packet = float(fix_tcptrace_time_bug(info[5]))
    last_packet = float(fix_tcptrace_time_bug(info[6]))
    return last_packet - first_packet


def get_relative_start_time(connections):
    """ Given a  dictionary of TCPConnection, return the smallest start time (0 of relative scale) """
    relative_start = float("inf")
    for conn_id, conn in connections.iteritems():
        start_time = conn.flow.attr[co.START]
        if start_time < relative_start:
            relative_start = start_time
    return relative_start


def extract_flow_data(out_file):
    """ Given an (open) file, return a dictionary of as many elements as there are tcp flows """
    # Return at the beginning of the file
    out_file.seek(0)
    raw_data = out_file.readlines()
    connections = {}
    # The replacement of whitespaces by nothing prevents possible bugs if we use
    # additional information from tcptrace
    data = map(lambda x: x.replace(" ", ""), raw_data)
    for line in data:
        # Case 1: line start with #; skip it
        if not line.startswith("#"):
            info = line.split(',')
            # Case 2: line is empty or line is the "header line"; skip it
            if len(info) > 1 and co.is_number(info[0]):
                # Case 3: line begin with number --> extract info
                conn = convert_number_to_name(int(info[0]) - 1)
                connection = TCPConnection(conn)
                connection.flow.attr[co.SADDR] = co.long_ipv6_address(info[1])
                connection.flow.attr[co.DADDR] = co.long_ipv6_address(info[2])
                connection.flow.attr[co.SPORT] = info[3]
                connection.flow.attr[co.DPORT] = info[4]
                connection.flow.detect_ipv4()
                connection.flow.indicates_wifi_or_cell()
                connection.flow.attr[co.START] = float(fix_tcptrace_time_bug(info[5]))
                connection.flow.attr[co.DURATION] = compute_duration(info)
                connection.flow.attr[co.S2D][co.PACKS] = int(info[7])
                connection.flow.attr[co.D2S][co.PACKS] = int(info[8])
                # Note that this count is about unique_data_bytes
                # Check for strange values (too high or negative)
                if int(info[21]) < 0 or int(info[21]) >= 100000000:
                    print("WARNING: strange value here S2D; see " + info[21] + " for " + conn)
                if int(info[22]) < 0 or int(info[22]) >= 100000000:
                    print("WARNING: strange value here D2S; see " + info[22] + " for " + conn)
                connection.flow.attr[co.S2D][co.BYTES] = int(info[21])
                connection.flow.attr[co.D2S][co.BYTES] = int(info[22])
                # This is about actual data bytes
                connection.flow.attr[co.S2D][co.BYTES_DATA] = int(info[25])
                connection.flow.attr[co.D2S][co.BYTES_DATA] = int(info[26])

                connection.flow.attr[co.S2D][co.PACKS_RETRANS] = int(info[27])
                connection.flow.attr[co.D2S][co.PACKS_RETRANS] = int(info[28])
                connection.flow.attr[co.S2D][co.BYTES_RETRANS] = int(info[29])
                connection.flow.attr[co.D2S][co.BYTES_RETRANS] = int(info[30])

                connection.flow.attr[co.S2D][co.PACKS_OOO] = int(info[35])
                connection.flow.attr[co.D2S][co.PACKS_OOO] = int(info[36])

                try:
                    connection.flow.attr[co.S2D][co.MISSED_DATA] = int(info[75])
                except ValueError:
                    # info[75] is 'NA'
                    connection.flow.attr[co.S2D][co.MISSED_DATA] = 0
                try:
                    connection.flow.attr[co.D2S][co.MISSED_DATA] = int(info[76])
                except ValueError:
                    # info[76] is 'NA'
                    connection.flow.attr[co.D2S][co.MISSED_DATA] = 0

                # Caution: -r must be set here!!
                if len(info) >= 101:
                    connection.flow.attr[co.S2D][co.RTT_SAMPLES] = int(info[89])
                    connection.flow.attr[co.D2S][co.RTT_SAMPLES] = int(info[90])
                    connection.flow.attr[co.S2D][co.RTT_MIN] = float(info[91])
                    connection.flow.attr[co.D2S][co.RTT_MIN] = float(info[92])
                    connection.flow.attr[co.S2D][co.RTT_MAX] = float(info[93])
                    connection.flow.attr[co.D2S][co.RTT_MAX] = float(info[94])
                    connection.flow.attr[co.S2D][co.RTT_AVG] = float(info[95])
                    connection.flow.attr[co.D2S][co.RTT_AVG] = float(info[96])
                    connection.flow.attr[co.S2D][co.RTT_STDEV] = float(info[97])
                    connection.flow.attr[co.D2S][co.RTT_STDEV] = float(info[98])
                    connection.flow.attr[co.S2D][co.RTT_3WHS] = float(info[99])
                    connection.flow.attr[co.D2S][co.RTT_3WHS] = float(info[100])


                # TODO maybe extract more information

                connection.attr[co.S2D][co.BYTES] = {}
                connection.attr[co.D2S][co.BYTES] = {}

                connections[conn] = connection

    return connections

##################################################
##        CONNECTION IDENTIFIER RELATED         ##
##################################################


def convert_number_to_letter(nb_conn):
    """ Given an integer, return the (nb_conn)th letter of the alphabet (zero-based index) """
    return chr(ord('a') + nb_conn)


def get_prefix_name(nb_conn):
    """ Given an integer, return the (nb_conn)th prefix, based on the alphabet (zero-based index)"""
    if nb_conn >= co.SIZE_LAT_ALPH:
        mod_nb = nb_conn % co.SIZE_LAT_ALPH
        div_nb = nb_conn / co.SIZE_LAT_ALPH
        return get_prefix_name(div_nb - 1) + convert_number_to_letter(mod_nb)
    else:
        return convert_number_to_letter(nb_conn)


def convert_number_to_name(nb_conn):
    """ Given an integer, return a name of type 'a2b', 'aa2ab',... """
    if nb_conn >= (co.SIZE_LAT_ALPH / 2):
        mod_nb = nb_conn % (co.SIZE_LAT_ALPH / 2)
        div_nb = nb_conn / (co.SIZE_LAT_ALPH / 2)
        prefix = get_prefix_name(div_nb - 1)
        return prefix + convert_number_to_letter(2 * mod_nb) + '2' + prefix \
            + convert_number_to_letter(2 * mod_nb + 1)
    else:
        return convert_number_to_letter(2 * nb_conn) + '2' + convert_number_to_letter(2 * nb_conn + 1)


def get_flow_name(xpl_filepath):
    """ Return the flow name in the form 'a2b' (and not 'b2a'), reverse is True iff in xpl_filepath,
        it contains 'b2a' instead of 'a2b'
    """
    xpl_fname = os.path.basename(xpl_filepath)
    # Basic information is contained between the two last '_'
    last_us_index = xpl_fname.rindex("_")
    nearly_last_us_index = xpl_fname.rindex("_", 0, last_us_index)
    flow_name = xpl_fname[nearly_last_us_index + 1:last_us_index]

    # Need to check if we need to reverse the flow name
    two_index = flow_name.index("2")
    left_letter = flow_name[two_index - 1]
    right_letter = flow_name[-1]
    if right_letter < left_letter:
        # Swap those two characters
        chars = list(flow_name)
        chars[two_index - 1] = right_letter
        chars[-1] = left_letter
        return ''.join(chars), True
    else:
        return flow_name, False


##################################################
##                   TCPTRACE                   ##
##################################################


def process_tcptrace_cmd(cmd, pcap_filepath, keep_csv=False, graph_dir_exp=None):
    """ Launch the command cmd given in argument, and return a dictionary containing information
        about connections of the pcap file analyzed
        Options -n, -l and --csv should be set
        Raise a TCPTraceError if tcptrace encounters problems
    """
    pcap_flow_data_path = pcap_filepath[:-5] + '_tcptrace.csv'
    flow_data_file = open(pcap_flow_data_path, 'w+')
    if subprocess.call(cmd, stdout=flow_data_file) != 0:
        raise TCPTraceError("Error of tcptrace with " + pcap_filepath)

    connections = extract_flow_data(flow_data_file)

    # Don't forget to close and remove pcap_flow_data
    flow_data_file.close()
    if keep_csv:
        try:
            shutil.move(pcap_flow_data_path, os.path.join(
                graph_dir_exp, co.CSV_DIR, os.path.basename(pcap_flow_data_path)))
        except IOError as e:
            print(str(e), file=sys.stderr)
    else:
        os.remove(pcap_flow_data_path)
    return connections


##################################################
##                RETRANSMISSION                ##
##################################################

def get_ip_port_tshark(str_data):
    """ Given the line of interest, return the ip and port
        Manage cases with IPv6 addresses
    """
    separator = str_data.rindex(":")
    ip = str_data[:separator]
    port = str_data[separator+1:]
    return ip, port


def get_total_and_retrans_frames(pcap_filepath, connections):
    """ Fill informations for connections based on tshark """
    # First init values to avoid strange errors if connection is empty
    for conn_id, conn in connections.iteritems():
        for direction in co.DIRECTIONS:
            connections[conn_id].flow.attr[direction][co.FRAMES_TOTAL] = 0
            connections[conn_id].flow.attr[direction][co.BYTES_FRAMES_TOTAL] = 0
            connections[conn_id].flow.attr[direction][co.FRAMES_RETRANS] = 0
            connections[conn_id].flow.attr[direction][co.BYTES_FRAMES_RETRANS] = 0

    stats_filename = os.path.basename(pcap_filepath)[:-5] + "_tshark_total"
    stats_file = open(stats_filename, 'w')
    co.tshark_stats(None, pcap_filepath, print_out=stats_file)
    stats_file.close()

    stats_file = open(stats_filename)
    data = stats_file.readlines()
    stats_file.close()
    for line in data:
        split_line = " ".join(line.split()).split(" ")
        if len(split_line) == 11:
            # Manage case with ipv6
            ip_src, port_src = get_ip_port_tshark(split_line[0])
            ip_dst, port_dst = get_ip_port_tshark(split_line[2])
            for conn_id, conn in connections.iteritems():
                if conn.flow.attr[co.SADDR] == ip_src and conn.flow.attr[co.SPORT] == port_src and conn.flow.attr[co.DADDR] == ip_dst and conn.flow.attr[co.DPORT]:
                    connections[conn_id].flow.attr[co.D2S][co.FRAMES_TOTAL] = int(split_line[3])
                    connections[conn_id].flow.attr[co.D2S][co.BYTES_FRAMES_TOTAL] = int(split_line[4])
                    connections[conn_id].flow.attr[co.S2D][co.FRAMES_TOTAL] = int(split_line[5])
                    connections[conn_id].flow.attr[co.S2D][co.BYTES_FRAMES_TOTAL] = int(split_line[6])
                    break
    stats_file.close()
    os.remove(stats_filename)

    stats_filename = os.path.basename(pcap_filepath)[:-5] + "_tshark_retrans"
    stats_file = open(stats_filename, 'w')
    co.tshark_stats('tcp.analysis.retransmission', pcap_filepath, print_out=stats_file)
    stats_file.close()

    stats_file = open(stats_filename)
    data = stats_file.readlines()
    stats_file.close()
    for line in data:
        split_line = " ".join(line.split()).split(" ")
        if len(split_line) == 11:
            ip_src, port_src = get_ip_port_tshark(split_line[0])
            ip_dst, port_dst = get_ip_port_tshark(split_line[2])
            for conn_id, conn in connections.iteritems():
                if conn.flow.attr[co.SADDR] == ip_src and conn.flow.attr[co.SPORT] == port_src and conn.flow.attr[co.DADDR] == ip_dst and conn.flow.attr[co.DPORT]:
                    connections[conn_id].flow.attr[co.D2S][co.FRAMES_RETRANS] = int(split_line[3])
                    connections[conn_id].flow.attr[co.D2S][co.BYTES_FRAMES_RETRANS] = int(split_line[4])
                    connections[conn_id].flow.attr[co.S2D][co.FRAMES_RETRANS] = int(split_line[5])
                    connections[conn_id].flow.attr[co.S2D][co.BYTES_FRAMES_RETRANS] = int(split_line[6])
                    break
    stats_file.close()
    os.remove(stats_filename)



##################################################
##               CLEANING RELATED               ##
##################################################


def get_connection_data_with_ip_port(connections, ip, port, dst=True):
    """ Get data for TCP connection with destination IP ip and port port in connections
        If no connection found, return None
        Support for dst=False will be provided if needed
    """
    for conn_id, conn in connections.iteritems():
        if conn.flow.attr[co.DADDR] == ip and conn.flow.attr[co.DPORT] == port:
            return conn

    # If reach this, no matching connection found
    return None


def merge_and_clean_sub_pcap(pcap_filepath, print_out=sys.stdout):
    """ Merge pcap files with name beginning with pcap_filepath (without extension) followed by two
        underscores and delete them
    """
    cmd = ['mergecap', '-w', pcap_filepath]
    for subpcap_filepath in glob.glob(pcap_filepath[:-5] + '__*.pcap'):
        cmd.append(subpcap_filepath)

    if subprocess.call(cmd, stdout=print_out) != 0:
        raise MergecapError("Error with mergecap " + pcap_filepath)

    for subpcap_filepath in cmd[3:]:
        os.remove(subpcap_filepath)


def split_and_replace(pcap_filepath, remain_pcap_filepath, conn, other_conn, num, print_out=sys.stdout):
    """ Split remain_pcap_filepath and replace DADDR and DPORT of conn by SADDR and DADDR of other_conn
        num will be the numerotation of the splitted file
        Can raise TSharkError, IOError or TCPRewriteError
    """
    # Split on the port criterion
    condition = '(tcp.srcport==' + \
        conn.flow.attr[co.SPORT] + \
        ')or(tcp.dstport==' + conn.flow.attr[co.SPORT] + ')'
    tmp_split_filepath = pcap_filepath[:-5] + "__tmp.pcap"
    co.tshark_filter(condition, remain_pcap_filepath, tmp_split_filepath, print_out=print_out)

    tmp_remain_filepath = pcap_filepath[:-5] + "__tmprem.pcap"
    condition = "!(" + condition + ")"
    co.tshark_filter(condition, remain_pcap_filepath, tmp_remain_filepath, print_out=print_out)

    shutil.move(tmp_remain_filepath, remain_pcap_filepath, print_out=print_out)

    # Replace meaningless IP and port with the "real" values
    split_filepath = pcap_filepath[:-5] + "__" + str(num) + ".pcap"
    cmd = ['tcprewrite',
           "--portmap=" +
           conn.flow.attr[co.DPORT] + ":" + other_conn.flow.attr[co.SPORT],
           "--pnat=" + conn.flow.attr[co.DADDR] +
           ":" + other_conn.flow.attr[co.SADDR],
           "--infile=" + tmp_split_filepath,
           "--outfile=" + split_filepath]
    if subprocess.call(cmd, stdout=print_out) != 0:
        raise TCPRewriteError("Error with tcprewrite " + conn.flow.attr[co.SPORT])

    os.remove(tmp_split_filepath)


def correct_trace(pcap_filepath, print_out=sys.stdout):
    """ Make the link between two unidirectional connections that form one bidirectional one
        Do this also for mptcp, because mptcptrace will not be able to find all conversations
    """
    cmd = ['tcptrace', '-n', '-l', '--csv', pcap_filepath]
    try:
        connections = process_tcptrace_cmd(cmd, pcap_filepath)
    except TCPTraceError as e:
        print(str(e) + ": skip tcp correction", file=sys.stderr)
        print(str(e) + ": stop correcting trace " + pcap_filepath, file=print_out)
        return
    # Create the remaining_file
    remain_pcap_filepath = co.copy_remain_pcap_file(
        pcap_filepath, print_out=print_out)
    if not remain_pcap_filepath:
        return

    num = 0
    for conn_id, conn in connections.iteritems():
        if conn.flow.attr[co.DADDR] == co.LOCALHOST_IPv4 and conn.flow.attr[co.DPORT] == co.PORT_RSOCKS:
            other_conn = get_connection_data_with_ip_port(
                connections, conn.flow.attr[co.SADDR], conn.flow.attr[co.SPORT])
            if other_conn:
                try:
                    split_and_replace(pcap_filepath, remain_pcap_filepath, conn, other_conn, num, print_out=print_out)
                    print(os.path.basename(pcap_filepath) + ": Corrected: " +
                          str(num) + "/" + str(len(connections)), file=print_out)
                except Exception as e:
                    print(str(e) + ": skip tcp correction", file=sys.stderr)
                    print(str(e) + ": stop correcting trace " + pcap_filepath, file=print_out)
                    return
        num += 1

    # Merge small pcap files into a unique one
    try:
        merge_and_clean_sub_pcap(pcap_filepath, print_out=print_out)
    except MergecapError as e:
        print(str(e) + ": skip tcp correction", file=sys.stderr)
        print(str(e) + ": stop correcting trace " + pcap_filepath, file=print_out)

    # For any traces, filter all connections that are not to proxy
    if 'any' in os.path.basename(pcap_filepath):
        # Split on the port criterion
        condition = '(ip.src==' + co.IP_PROXY + ')or(ip.dst==' + co.IP_PROXY + ')'
        tmp_filter_filepath = pcap_filepath[:-5] + "__tmp_any.pcap"
        try:
            co.tshark_filter(condition, pcap_filepath, tmp_filter_filepath, print_out=print_out)
            shutil.move(tmp_filter_filepath, pcap_filepath, print_out=print_out)
        except Exception as e:
            print(str(e) + ": clean skipped", file=sys.stderr)

    print(pcap_filepath + ": cleaning done")

##################################################
##                   TCPTRACE                   ##
##################################################


def interesting_graph(flow_name, is_reversed, connections):
    """ Return True if the MPTCP graph is worthy, else False
        This function assumes that a graph is interesting if it has at least one connection that
        is not 127.0.0.1 -> 127.0.0.1 and if there are data packets sent
    """
    if (not connections[flow_name].flow.attr[co.TYPE] == co.IPv4 or connections[flow_name].flow.attr[co.IF]):
        direction = co.D2S if is_reversed else co.S2D
        return (connections[flow_name].flow.attr[direction][co.PACKS] > 0)

    return False


def prepare_xpl_file(xpl_filepath, connections, flow_name, relative_start):
    """ Rewrite xpl file, set relative values of time for all connections in a pcap
        Return a list of lists to create a fully aggregated graph
    """
    connection = connections[flow_name]
    try:
        # First read the file
        xpl_file = open(xpl_filepath, 'r')
    except IOError:
        # Sometimes, no datasets file; skip the file
        return
    try:
        datasets = xpl_file.readlines()
        xpl_file.close()
        # Then overwrite it
        time_offset = connection.flow.attr[co.START] - relative_start
        xpl_file = open(xpl_filepath, 'w')
        for line in datasets:
            split_line = line.split(" ")
            if split_line[0] in co.XPL_ONE_POINT:
                time = float(split_line[1]) + time_offset
                xpl_file.write(split_line[0] + " " + str(time) + " " + str(int(split_line[2])) + "\n")
            elif split_line[0] in co.XPL_TWO_POINTS:
                time_1 = float(split_line[1]) + time_offset
                time_2 = float(split_line[3]) + time_offset
                xpl_file.write(split_line[0] + " " + str(time_1) + " " + str(
                    int(split_line[2])) + " " + str(time_2) + " " + str(int(split_line[4])) + "\n")
            else:  # Not a data line, write it as it is
                xpl_file.write(line)

        xpl_file.close()
    except IOError as e:
        print(e, file=sys.stderr)
        print("IOError in preparing xpl file of " + xpl_filepath, file=sys.stderr)


def get_upper_packets_in_flight_and_adv_rwin(xpl_filepath, flow_name):
    """ Read the file with path xpl_filepath and collect upper bound of packet in flight and advertised
        receiver window and return a tuple with a list ready to aggregate and the list of values of
        advertised window of receiver
    """
    is_adv_rwin = False
    aggregate_seq = []
    adv_rwin = []
    max_seq = 0
    try:
        # First read the file
        xpl_file = open(xpl_filepath, 'r')
        data = xpl_file.readlines()
        xpl_file.close()
        # Then collect all useful data
        for line in data:
            if line.startswith("uarrow") or line.startswith("diamond"):
                is_adv_rwin = False
                split_line = line.split(" ")
                if ((not split_line[0] == "diamond") or (len(split_line) == 4 and "white" in split_line[3])):
                    time = float(split_line[1])
                    aggregate_seq.append([time, int(split_line[2]), flow_name])
                    max_seq = max(max_seq, int(split_line[2]))
            elif line.startswith("yellow"):
                is_adv_rwin = True
            elif is_adv_rwin and line.startswith("line"):
                split_line = line.split(" ")
                time_1 = float(split_line[1])
                seq_1 = int(split_line[2])
                time_2 = float(split_line[3])
                seq_2 = int(split_line[4])
                adv_rwin.append([time_1, seq_1])
                adv_rwin.append([time_2, seq_2])
            else:
                is_adv_rwin = False

    except IOError as e:
        print(e, file=sys.stderr)
        print("IOError in reading file " + xpl_filepath, file=sys.stderr)
    return aggregate_seq, adv_rwin


def get_flow_name_connection(connection, connections):
    """ Return the connection id and flow id in MPTCP connections of the TCP connection
        Same if same source/dest ip/port
        If not found, return None, None
    """
    for conn_id, conn in connections.iteritems():
        # Let a little margin, but don't think it's needed
        if (connection.flow.attr[co.START] >= conn.attr[co.START] - 120.0 and
            connection.flow.attr[co.START] + connection.flow.attr[co.DURATION] <= conn.attr[co.START] + conn.attr[co.DURATION] + 120.0):
            for flow_id, flow in conn.flows.iteritems():
                if (connection.flow.attr[co.SADDR] == flow.attr[co.SADDR] and
                        connection.flow.attr[co.DADDR] == flow.attr[co.DADDR] and
                        connection.flow.attr[co.SPORT] == flow.attr[co.SPORT] and
                        connection.flow.attr[co.DPORT] == flow.attr[co.DPORT]):
                    return conn_id, flow_id

    return None, None


def copy_info_to_mptcp_connections(connection, mptcp_connections, failed_conns, acksize_all, acksize_all_mptcp, flow_name, light=False):
    """ Given a tcp connection, copy its start and duration to the corresponding mptcp connection
        If connection is a failed subflow of a MPTCPConnection, add it in failed_conns
        Return the corresponding connection and flow ids of the mptcp connection
    """
    conn_id, flow_id = get_flow_name_connection(connection, mptcp_connections)
    if conn_id:
        mptcp_connections[conn_id].flows[flow_id].subflow_id = flow_name
        mptcp_connections[conn_id].flows[flow_id].attr[co.START] = connection.flow.attr[co.START]
        mptcp_connections[conn_id].flows[flow_id].attr[co.DURATION] = connection.flow.attr[co.DURATION]
        for direction in co.DIRECTIONS:
            mptcp_connections[conn_id].flows[flow_id].attr[direction][co.PACKS] = connection.flow.attr[direction][co.PACKS]
            mptcp_connections[conn_id].flows[flow_id].attr[direction][co.PACKS_RETRANS] = connection.flow.attr[direction][co.PACKS_RETRANS]
            mptcp_connections[conn_id].flows[flow_id].attr[direction][co.BYTES_RETRANS] = connection.flow.attr[direction][co.BYTES_RETRANS]
            mptcp_connections[conn_id].flows[flow_id].attr[direction][co.PACKS_OOO] = connection.flow.attr[direction][co.PACKS_OOO]
            mptcp_connections[conn_id].flows[flow_id].attr[direction][co.BYTES_DATA] = connection.flow.attr[direction][co.BYTES_DATA]
            mptcp_connections[conn_id].flows[flow_id].attr[direction][co.MISSED_DATA] = connection.flow.attr[direction][co.MISSED_DATA]
            mptcp_connections[conn_id].flows[flow_id].attr[direction][co.TIMESTAMP_RETRANS] = connection.flow.attr[direction][co.TIMESTAMP_RETRANS]

            if co.RTT_SAMPLES in connection.flow.attr[direction]:
                mptcp_connections[conn_id].flows[flow_id].attr[direction][co.RTT_SAMPLES] = connection.flow.attr[direction][co.RTT_SAMPLES]
                mptcp_connections[conn_id].flows[flow_id].attr[direction][co.RTT_MIN] = connection.flow.attr[direction][co.RTT_MIN]
                mptcp_connections[conn_id].flows[flow_id].attr[direction][co.RTT_MAX] = connection.flow.attr[direction][co.RTT_MAX]
                mptcp_connections[conn_id].flows[flow_id].attr[direction][co.RTT_AVG] = connection.flow.attr[direction][co.RTT_AVG]
                mptcp_connections[conn_id].flows[flow_id].attr[direction][co.RTT_STDEV] = connection.flow.attr[direction][co.RTT_STDEV]
                mptcp_connections[conn_id].flows[flow_id].attr[direction][co.RTT_3WHS] = connection.flow.attr[direction][co.RTT_3WHS]

            if co.BYTES_FRAMES_RETRANS in connection.flow.attr[direction]:
                mptcp_connections[conn_id].flows[flow_id].attr[direction][co.BYTES_FRAMES_RETRANS] = connection.flow.attr[direction][co.BYTES_FRAMES_RETRANS]
                mptcp_connections[conn_id].flows[flow_id].attr[direction][co.FRAMES_RETRANS] = connection.flow.attr[direction][co.FRAMES_RETRANS]

            if flow_name in acksize_all[direction]:
                if conn_id not in acksize_all_mptcp[direction]:
                    acksize_all_mptcp[direction][conn_id] = {}
                acksize_all_mptcp[direction][conn_id][flow_id] = acksize_all[direction][flow_name]

    else:
        # This is a TCPConnection that failed to be a MPTCP subflow: add it in failed_conns
        failed_conns[connection.conn_id] = connection

    return conn_id, flow_id


def append_as_third_to_all_elements(lst, element):
    """ Append element at index 2 to all lists in the list lst
        Lists are assumed to have at least 2 elements, and output will have 3
    """
    return_list = []
    for elem in lst:
        return_list.append([elem[0], elem[1], element])
    return return_list


def create_congestion_window_data(tsg, adv_rwin, pcap_filepath, cwin_data_all, is_reversed, connections, flow_name, mptcp_connections, conn_id, flow_id):
    """ With the time sequence data and the advertised receiver window, generate data of estimated
        congestion control
        Set the congestion data in the cwin_data_all dictionary
    """
    tsg_list = append_as_third_to_all_elements(tsg, 'tsg')
    adv_rwin_list = append_as_third_to_all_elements(adv_rwin, 'adv_rwin')
    all_data_list = sorted(tsg_list + adv_rwin_list, key=lambda elem: elem[0])
    congestion_list = []
    congestion_value = 0
    offsets = {'tsg': 0, 'adv_rwin': 0}
    for elem in all_data_list:
        if elem[2] == 'tsg':
            congestion_value -= elem[1] - offsets['tsg']
        elif elem[2] == 'adv_rwin':
            congestion_value += elem[1] - offsets['adv_rwin']

        offsets[elem[2]] = elem[1]
        congestion_list.append([elem[0], congestion_value])

    pcap_filename = os.path.basename(pcap_filepath[:-5])

    if mptcp_connections:
        if not conn_id:
            return
        cwin_name = pcap_filename + "_" + conn_id
        interface = mptcp_connections[conn_id].flows[flow_id].attr[co.IF] + '-' + flow_id
    else:
        cwin_name = pcap_filename + "_" + flow_name
        interface = connections[flow_name].flow.attr[co.IF]

    if cwin_name not in cwin_data_all.keys():
        cwin_data_all[cwin_name] = {}

    if is_reversed:
        if co.D2S not in cwin_data_all[cwin_name].keys():
            cwin_data_all[cwin_name][co.D2S] = {}
        cwin_data_all[cwin_name][co.D2S][interface] = congestion_list
    else:
        if co.S2D not in cwin_data_all[cwin_name].keys():
            cwin_data_all[cwin_name][co.S2D] = {}
        cwin_data_all[cwin_name][co.S2D][interface] = congestion_list


def plot_congestion_graphs(pcap_filepath, graph_dir_exp, cwin_data_all):
    """ Given cwin data of all connections, plot their congestion graph """
    cwin_graph_dir = os.path.join(graph_dir_exp, co.CWIN_DIR)

    for cwin_name, cwin_data in cwin_data_all.iteritems():
        base_graph_fname = cwin_name + '_cwin'

        for direction, data_if in cwin_data.iteritems():
            dir_abr = 'd2s' if direction == co.D2S else 's2d' if direction == co.S2D else '?'
            base_dir_graph_fname = base_graph_fname + '_' + dir_abr

            for interface, data in data_if.iteritems():
                graph_fname = base_dir_graph_fname + '_' + interface
                graph_fname += '.pdf'
                graph_filepath = os.path.join(cwin_graph_dir, graph_fname)
                co.plot_line_graph([data], [interface], ['k'], "Time [s]",
                                   "Congestion window [Bytes]", "Congestion window", graph_filepath, ymin=0)


def collect_retrans_acksize_xpl(pcap_filepath, xpl_filepath, connections, acksize_dict, flow_name, is_reversed):
    direction = co.D2S if is_reversed else co.S2D
    retrans_ts = []
    acksize_conn = {}
    if connections[flow_name].flow.attr[direction][co.PACKS_RETRANS] == 0:
        connections[flow_name].flow.attr[direction][co.TIMESTAMP_RETRANS] = retrans_ts
        return
    try:
        # First read the file
        xpl_file = open(xpl_filepath, 'r')
    except IOError as e:
        print(str(e), file=sys.stderr)
        # Sometimes, no datasets file; skip the file
        connections[flow_name].flow.attr[direction][co.TIMESTAMP_RETRANS] = retrans_ts
        return
    data = xpl_file.readlines()
    xpl_file.close()
    take_next = False
    green_line = False
    next_is_ack = False
    for line in data:
        if take_next:
            split_line = line.split(" ")
            if split_line[0] in co.XPL_ONE_POINT:
                retrans_ts.append(float(split_line[1]))
                take_next = False
        elif line.startswith("R"):
            take_next = True
        elif line.startswith("green"):
            green_line = True
        elif green_line and next_is_ack:
            # This is the vertical line: take it
            split_line = line.split(" ")
            if split_line[0] == "line":
                if len(split_line) >= 5:
                    acksize = int(split_line[4]) - int(split_line[2])
                    if acksize not in acksize_conn:
                        acksize_conn[acksize] = 1
                    else:
                        acksize_conn[acksize] += 1
            elif split_line[0] == "dtick":
                # Ack size == 0
                if 0 not in acksize_conn:
                    acksize_conn[0] = 1
                else:
                    acksize_conn[0] += 1
            green_line = False
            next_is_ack = False
        elif green_line and line.startswith("line"):
            # This is the horizontal line, not interested in
            next_is_ack = True

    connections[flow_name].flow.attr[direction][co.TIMESTAMP_RETRANS] = retrans_ts
    acksize_dict[direction][flow_name] = acksize_conn


def process_tsg_xpl_file(pcap_filepath, xpl_filepath, graph_dir_exp, connections, aggregate_dict, cwin_data_all, flow_name, relative_start, is_reversed, mptcp_connections, conn_id, flow_id):
    """ Prepare gpl file for the (possible) plot and aggregate its content
        Also update connections or mptcp_connections with the processed data
    """
    if not mptcp_connections:
        prepare_xpl_file(xpl_filepath, connections, flow_name, relative_start)
        aggregate_tsg, adv_rwin = get_upper_packets_in_flight_and_adv_rwin(xpl_filepath, flow_name)
        create_congestion_window_data(
            aggregate_tsg, adv_rwin, pcap_filepath, cwin_data_all, is_reversed, connections, flow_name, mptcp_connections, conn_id, flow_id)
    interface = connections[flow_name].flow.attr[co.IF]
    direction = co.D2S if is_reversed else co.S2D
    if mptcp_connections:
        if conn_id:
            mptcp_connections[conn_id].flows[flow_id].attr[direction][co.BYTES] = connections[flow_name].flow.attr[direction][co.BYTES]
            if interface in mptcp_connections[conn_id].attr[direction][co.BYTES]:
                mptcp_connections[conn_id].attr[direction][co.BYTES][interface] += connections[flow_name].flow.attr[direction][co.BYTES]
            else:
                mptcp_connections[conn_id].attr[direction][co.BYTES][interface] = connections[flow_name].flow.attr[direction][co.BYTES]
    else:
        connections[flow_name].attr[direction][co.BYTES][interface] = connections[flow_name].flow.attr[direction][co.BYTES]


def plot_aggregated_results(pcap_filepath, graph_dir_exp, aggregate_dict):
    """ Create graphs for aggregated results """
    aggl_dir = os.path.join(graph_dir_exp, co.AGGL_DIR)
    for direction, interfaces in aggregate_dict.iteritems():
        for interface, aggr_list in interfaces.iteritems():
            aggregate_dict[direction][interface] = co.sort_and_aggregate(aggr_list)
            co.plot_line_graph([aggregate_dict[direction][interface]], [interface], ['k'], "Time [s]",
                               "Sequence number", "Agglomeration of " + interface + " connections", os.path.join(
                               aggl_dir, os.path.basename(pcap_filepath)[:-5] + "_" + direction + "_" + interface
                               + '.pdf'))

        co.plot_line_graph(aggregate_dict[direction].values(), aggregate_dict[direction].keys(), ['r:', 'b--'],
                           "Time [s]", "Sequence number", "Agglomeration of all connections", os.path.join(
                           aggl_dir, os.path.basename(pcap_filepath)[:-5] + "_" + direction + "_all.pdf"))


def collect_throughput(xpl_filepath, connections, flow_name, is_reversed):
    """ Add throughput information to connections """
    try:
        xpl_file = open(xpl_filepath)
        data = xpl_file.readlines()
        xpl_file.close()
        tput_data = []

        next_interesting = False
        for line in data:
            if next_interesting and 'dot' in line:
                # Interested in lines starting with dot
                tput_data.append(int(line.split(' ')[2]))
                next_interesting = False
            elif line.startswith('red'):
                next_interesting = True

        if len(tput_data) > 0:
            direction = co.D2S if is_reversed else co.S2D
            connections[flow_name].flow.attr[direction][co.THGPT_TCPTRACE] = np.mean(tput_data)

    except IOError as e:
        print(e, file=sys.stderr)
        print("No throughput data for " + xpl_filepath, file=sys.stderr)


def extract_rtt_from_xpl(xpl_filepath):
    """ Given the filepath of a xpl file containing RTT info, returns an array of the values of the RTT """
    try:
        xpl_file = open(xpl_filepath)
        data = xpl_file.readlines()
        xpl_file.close()
    except IOError as e:
        print(str(e), file=sys.stderr)
        return []

    rtts = []
    for line in data:
        split_line = line.split(" ")
        if split_line[0] == 'dot':
            rtts.append(float(split_line[2]))

    return rtts


def collect_rtt(xpl_filepath, rtt_all, flow_name, is_reversed, connections):
    """ Store in rtt_all all RTTs perceived for the connection flow_name """
    direction = co.D2S if is_reversed else co.S2D
    rtts = extract_rtt_from_xpl(xpl_filepath)
    rtt_all[direction][flow_name] = rtts
    if rtts:
        try:
            np_rtts = np.array(rtts)
            # Those info are stored in the connection itself, and not in flow, because app delay is at connection level for TCP
            connections[flow_name].attr[direction][co.RTT_99P] = np.percentile(np_rtts, 99)
            connections[flow_name].attr[direction][co.RTT_98P] = np.percentile(np_rtts, 98)
            connections[flow_name].attr[direction][co.RTT_97P] = np.percentile(np_rtts, 97)
            connections[flow_name].attr[direction][co.RTT_95P] = np.percentile(np_rtts, 95)
            connections[flow_name].attr[direction][co.RTT_90P] = np.percentile(np_rtts, 90)
            connections[flow_name].attr[direction][co.RTT_75P] = np.percentile(np_rtts, 75)
            connections[flow_name].attr[direction][co.RTT_MED] = np.percentile(np_rtts, 50)
            connections[flow_name].attr[direction][co.RTT_25P] = np.percentile(np_rtts, 25)
        except ValueError as e:
            print(str(e), xpl_filepath)


def collect_rtt_subflow(xpl_filepath, rtt_all, conn_id, flow_id, is_reversed, mptcp_connections):
    """ Store in rtt_all all RTTs perceived by subflow for conn_id by interface """
    if not conn_id or not flow_id:
        return
    direction = co.D2S if is_reversed else co.S2D
    interface = mptcp_connections[conn_id].flows[flow_id].attr[co.IF]
    if conn_id not in rtt_all[direction]:
        rtt_all[direction][conn_id] = {}
    rtts = extract_rtt_from_xpl(xpl_filepath)
    rtt_all[direction][conn_id][interface] = rtts
    if rtts:
        try:
            np_rtts = np.array(rtts)
            # Those info are stored in the flows because these are not directly related to MPTCP, but to its flows
            mptcp_connections[conn_id].flows[flow_id].attr[direction][co.RTT_99P] = np.percentile(np_rtts, 99)
            mptcp_connections[conn_id].flows[flow_id].attr[direction][co.RTT_98P] = np.percentile(np_rtts, 98)
            mptcp_connections[conn_id].flows[flow_id].attr[direction][co.RTT_97P] = np.percentile(np_rtts, 97)
            mptcp_connections[conn_id].flows[flow_id].attr[direction][co.RTT_95P] = np.percentile(np_rtts, 95)
            mptcp_connections[conn_id].flows[flow_id].attr[direction][co.RTT_90P] = np.percentile(np_rtts, 90)
            mptcp_connections[conn_id].flows[flow_id].attr[direction][co.RTT_75P] = np.percentile(np_rtts, 75)
            mptcp_connections[conn_id].flows[flow_id].attr[direction][co.RTT_MED] = np.percentile(np_rtts, 50)
            mptcp_connections[conn_id].flows[flow_id].attr[direction][co.RTT_25P] = np.percentile(np_rtts, 25)
        except ValueError as e:
            print(str(e), xpl_filepath)


def retransmissions_tcpcsm(pcap_filepath, connections):
    cmd = ['tcpcsm', '-o', pcap_filepath[:-5] + '_tcpcsm', '-R', pcap_filepath]
    try:
        if subprocess.call(cmd) != 0:
            return
    except Exception as e:
        print(str(e), file=sys.stderr)
        return

    # Create a reversed dictionary to speed up the lookup
    inverse_dict = create_inverse_dictionary(connections)

    tcpcsm_file = open(pcap_filepath[:-5] + '_tcpcsm')
    data = tcpcsm_file.readlines()
    tcpcsm_file.close()

    for line in data:
        split_line = line.split()
        if split_line[6] in ['RTO', 'FRETX', 'MS_FRETX', 'SACK_FRETX', 'BAD_FRETX', 'LOSS_REC', 'UNEXP_FREC', 'UNNEEDED']:
            key = (split_line[1], split_line[0], split_line[3], split_line[2])
            if len(inverse_dict.get(key, [])) == 1:
                conn_id, flow_id = inverse_dict[key][0]
                direction = co.S2D if split_line[5] == '1' else co.D2S
                if co.TCPCSM_RETRANS not in connections[conn_id].flows[flow_id].attr[direction]:
                    connections[conn_id].flows[flow_id].attr[direction][co.TCPCSM_RETRANS] = [(split_line[7], split_line[6])]
                else:
                    connections[conn_id].flows[flow_id].attr[direction][co.TCPCSM_RETRANS] += [(split_line[7], split_line[6])]

    os.remove(pcap_filepath[:-5] + '_tcpcsm')


def create_inverse_dictionary(connections):
    inverse = {}
    for conn_id, conn in connections.iteritems():
        for flow_id, flow in conn.iteritems():
            key = (flow.attr[co.SADDR], flow.attr[co.DADDR], flow.attr[co.SPORT], flow.attr[co.DPORT])
            if key not in inverse:
                inverse[key] = [(conn_id, flow_id)]
            else:
                inverse[key] += [(conn_id, flow_id)]

    return inverse


def process_trace(pcap_filepath, graph_dir_exp, stat_dir_exp, aggl_dir_exp, rtt_dir_exp, rtt_subflow_dir_exp, failed_conns_dir_exp, acksize_tcp_dir_exp, plot_cwin, tcpcsm, mptcp_connections=None, print_out=sys.stdout, min_bytes=0, light=False):
    """ Process a tcp pcap file and generate graphs of its connections """
    # -C for color, -S for sequence numbers, -T for throughput graph
    # -zxy to plot both axes to 0
    # -n to avoid name resolution
    # -y to remove some noise in sequence graphs
    # -l for long output
    # --csv for csv file
    cmd = ['tcptrace', '--output_dir=' + os.getcwd(),
           '--output_prefix=' +
           os.path.basename(pcap_filepath[:-5]) + '_', '-C', '-S']
    if not light:
        cmd += ['-T', '-A250', '-R']
    cmd += ['-zxy', '-n', '-y', '-l', '--csv', '-r', pcap_filepath]

    try:
        connections = process_tcptrace_cmd(cmd, pcap_filepath, keep_csv=True, graph_dir_exp=graph_dir_exp)
    except TCPTraceError as e:
        print(str(e) + ": skip process", file=sys.stderr)
        return

    cmd = ['tcptrace', '--output_dir=' + os.getcwd(),
           '--output_prefix=' +
           os.path.basename(pcap_filepath[:-5]) + '_', '-C', '-R']
    cmd += ['-zxy', '-n', '-y', pcap_filepath]
    devnull = open(os.devnull, 'w')
    if subprocess.call(cmd, stdout=devnull) != 0:
        raise TCPTraceError("Error of tcptrace with " + pcap_filepath)
    devnull.close()

    if not light:
        get_total_and_retrans_frames(pcap_filepath, connections)

    relative_start = get_relative_start_time(connections)
    aggregate_dict = {
        co.S2D: {co.WIFI: [], co.CELL: []}, co.D2S: {co.WIFI: [], co.CELL: []}}

    # The dictionary where all cwin data of the scenario will be stored
    cwin_data_all = {}
    # The dictionary where all RTTs will be stored
    rtt_all = {co.S2D: {}, co.D2S: {}}
    # Directory containing all TCPConnections that tried to be MPTCP subflows, but failed to
    failed_conns = {}

    if tcpcsm:
        retransmissions_tcpcsm(pcap_filepath, connections)

    acksize_all = {co.D2S: {}, co.S2D: {}}
    acksize_all_mptcp = {co.D2S: {}, co.S2D: {}}

    for xpl_filepath in glob.glob(os.path.join(os.getcwd(), os.path.basename(pcap_filepath[:-5]) + '_*.xpl')):
        conn_id, flow_id = None, None
        flow_name, is_reversed = get_flow_name(xpl_filepath)
        collect_retrans_acksize_xpl(pcap_filepath, xpl_filepath, connections, acksize_all, flow_name, is_reversed)

    # The tcptrace call will generate .xpl files to cope with
    for xpl_filepath in glob.glob(os.path.join(os.getcwd(), os.path.basename(pcap_filepath[:-5]) + '_*.xpl')):
        flow_name, is_reversed = get_flow_name(xpl_filepath)
        if mptcp_connections:
            conn_id, flow_id = copy_info_to_mptcp_connections(connections[flow_name], mptcp_connections, failed_conns, acksize_all, acksize_all_mptcp, flow_name, light=light)

        if interesting_graph(flow_name, is_reversed, connections) and 'tsg' in os.path.basename(xpl_filepath):
            process_tsg_xpl_file(pcap_filepath, xpl_filepath, graph_dir_exp, connections, aggregate_dict, cwin_data_all,
                                 flow_name, relative_start, is_reversed, mptcp_connections, conn_id, flow_id)
        elif 'tput' in os.path.basename(xpl_filepath) and not mptcp_connections and not light:
            collect_throughput(xpl_filepath, connections, flow_name, is_reversed)

        try:
            if mptcp_connections:
                # If mptcp, don't keep tcptrace plots, except RTT ones
                if '_rtt.xpl' in os.path.basename(xpl_filepath):
                    # if not light:
                    collect_rtt_subflow(xpl_filepath, rtt_all, conn_id, flow_id, is_reversed, mptcp_connections)
                    #co.move_file(xpl_filepath, os.path.join(graph_dir_exp, co.DEF_RTT_DIR))
                # else:
                if not light and 'tsg' in os.path.basename(xpl_filepath):
                    co.move_file(xpl_filepath, os.path.join(graph_dir_exp, co.TSG_THGPT_DIR))
                else:
                    os.remove(xpl_filepath)
            else:
                if '_rtt.xpl' in os.path.basename(xpl_filepath):
                    if not light:
                        collect_rtt(xpl_filepath, rtt_all, flow_name, is_reversed, connections)
                    co.move_file(xpl_filepath, os.path.join(graph_dir_exp, co.DEF_RTT_DIR))
                else:
                    co.move_file(xpl_filepath, os.path.join(graph_dir_exp, co.TSG_THGPT_DIR))
        except OSError as e:
            print(str(e) + ": skipped", file=sys.stderr)
        except IOError as e:
            print(str(e) + ": skipped", file=sys.stderr)

    if plot_cwin:
        plot_aggregated_results(pcap_filepath, graph_dir_exp, aggregate_dict)

    # Save aggregated graphs (even it's not connections)
    co.save_data(pcap_filepath, aggl_dir_exp, aggregate_dict)

    # Save connections info
    if mptcp_connections:
        co.save_data(pcap_filepath, acksize_tcp_dir_exp, acksize_all_mptcp)
        # First save RTT data of subflows
        co.save_data(pcap_filepath, rtt_subflow_dir_exp, rtt_all)
        # Also save TCP connections that failed to be MPTCP subflows
        co.save_data(pcap_filepath, failed_conns_dir_exp, failed_conns)
        # Returns to the caller the data to plot cwin
        return cwin_data_all
    else:
        if plot_cwin:
            plot_congestion_graphs(pcap_filepath, graph_dir_exp, cwin_data_all)
        co.save_data(pcap_filepath, acksize_tcp_dir_exp, acksize_all)
        co.save_data(pcap_filepath, rtt_dir_exp, rtt_all)
        co.save_data(pcap_filepath, stat_dir_exp, connections)


def process_trace_directory(directory_path, graph_dir_exp, stat_dir_exp, aggl_dir_exp, rtt_dir_exp, rtt_subflow_dir_exp, failed_conns_dir_exp, acksize_tcp_dir_exp, plot_cwin, tcpcsm, mptcp_connections=None, print_out=sys.stdout, min_bytes=0, light=False):
    """ Process a tcp pcap file and generate graphs of its connections """
    cwd = os.getcwd()
    os.chdir(directory_path)
    # -C for color, -S for sequence numbers, -T for throughput graph
    # -zxy to plot both axes to 0
    # -n to avoid name resolution
    # -y to remove some noise in sequence graphs
    # -l for long output
    # --csv for csv file
    cmd = ['tcptrace', '--output_dir=' + os.getcwd(),
           '--output_prefix=' +
           os.path.basename(directory_path[:-5]) + '_', '-C', '-S']
    if not light:
        cmd += ['-T', '-A250', '-R']
    cmd += ['-zxy', '-n', '-y', '-l', '--csv', '-r'] + glob.glob(os.path.join(os.getcwd(), '*.pcap'))

    try:
        # Compatibility hack
        connections = process_tcptrace_cmd(cmd, directory_path + '.pcap', keep_csv=True, graph_dir_exp=graph_dir_exp)
    except TCPTraceError as e:
        print(str(e) + ": skip process", file=sys.stderr)
        return

    cmd = ['tcptrace', '--output_dir=' + os.getcwd(),
           '--output_prefix=' +
           os.path.basename(directory_path[:-5]) + '_', '-C', '-R']
    cmd += ['-zxy', '-n', '-y'] + glob.glob(os.path.join(os.getcwd(), '*.pcap'))
    devnull = open(os.devnull, 'w')
    if subprocess.call(cmd, stdout=devnull) != 0:
        raise TCPTraceError("Error of tcptrace with " + directory_path)
    devnull.close()

    if not light:
        # Compatibility hack
        get_total_and_retrans_frames(directory_path + '.pcap', connections)

    relative_start = get_relative_start_time(connections)
    aggregate_dict = {
        co.S2D: {co.WIFI: [], co.CELL: []}, co.D2S: {co.WIFI: [], co.CELL: []}}

    # The dictionary where all cwin data of the scenario will be stored
    cwin_data_all = {}
    # The dictionary where all RTTs will be stored
    rtt_all = {co.S2D: {}, co.D2S: {}}
    # Directory containing all TCPConnections that tried to be MPTCP subflows, but failed to
    failed_conns = {}

    if tcpcsm:
        retransmissions_tcpcsm(directory_path + '.pcap', connections)

    acksize_all = {co.D2S: {}, co.S2D: {}}
    acksize_all_mptcp = {co.D2S: {}, co.S2D: {}}

    print("Collect retrans acksize")

    for xpl_filepath in glob.glob(os.path.join(os.getcwd(), '*.xpl')):
        conn_id, flow_id = None, None
        flow_name, is_reversed = get_flow_name(xpl_filepath)
        collect_retrans_acksize_xpl(directory_path + '.pcap', xpl_filepath, connections, acksize_all, flow_name, is_reversed)

    print("Match MPTCP and TCP connections")

    # The tcptrace call will generate .xpl files to cope with
    for xpl_filepath in glob.glob(os.path.join(os.getcwd(), '*.xpl')):
        flow_name, is_reversed = get_flow_name(xpl_filepath)
        if mptcp_connections:
            conn_id, flow_id = copy_info_to_mptcp_connections(connections[flow_name], mptcp_connections, failed_conns, acksize_all, acksize_all_mptcp, flow_name, light=light)

        if interesting_graph(flow_name, is_reversed, connections) and 'tsg' in os.path.basename(xpl_filepath):
            process_tsg_xpl_file(directory_path + '.pcap', xpl_filepath, graph_dir_exp, connections, aggregate_dict, cwin_data_all,
                                 flow_name, relative_start, is_reversed, mptcp_connections, conn_id, flow_id)
        elif 'tput' in os.path.basename(xpl_filepath) and not mptcp_connections and not light:
            collect_throughput(xpl_filepath, connections, flow_name, is_reversed)

        try:
            if mptcp_connections:
                # If mptcp, don't keep tcptrace plots, except RTT ones
                if '_rtt.xpl' in os.path.basename(xpl_filepath):
                    # if not light:
                    collect_rtt_subflow(xpl_filepath, rtt_all, conn_id, flow_id, is_reversed, mptcp_connections)
                    #co.move_file(xpl_filepath, os.path.join(graph_dir_exp, co.DEF_RTT_DIR))
                # else:
                if not light and 'tsg' in os.path.basename(xpl_filepath):
                    co.move_file(xpl_filepath, os.path.join(graph_dir_exp, co.TSG_THGPT_DIR))
                else:
                    os.remove(xpl_filepath)
            else:
                if '_rtt.xpl' in os.path.basename(xpl_filepath):
                    if not light:
                        collect_rtt(xpl_filepath, rtt_all, flow_name, is_reversed, connections)
                    co.move_file(xpl_filepath, os.path.join(graph_dir_exp, co.DEF_RTT_DIR))
                else:
                    co.move_file(xpl_filepath, os.path.join(graph_dir_exp, co.TSG_THGPT_DIR))
        except OSError as e:
            print(str(e) + ": skipped", file=sys.stderr)
        except IOError as e:
            print(str(e) + ": skipped", file=sys.stderr)

    os.chdir(cwd)

    if plot_cwin:
        plot_aggregated_results(directory_path + '.pcap', graph_dir_exp, aggregate_dict)

    # Save aggregated graphs (even it's not connections)
    co.save_data(directory_path + '.pcap', aggl_dir_exp, aggregate_dict)

    # Save connections info
    if mptcp_connections:
        co.save_data(directory_path + '.pcap', acksize_tcp_dir_exp, acksize_all_mptcp)
        # First save RTT data of subflows
        co.save_data(directory_path + '.pcap', rtt_subflow_dir_exp, rtt_all)
        # Also save TCP connections that failed to be MPTCP subflows
        co.save_data(directory_path + '.pcap', failed_conns_dir_exp, failed_conns)
        # Returns to the caller the data to plot cwin
        return cwin_data_all
    else:
        if plot_cwin:
            plot_congestion_graphs(directory_path + '.pcap', graph_dir_exp, cwin_data_all)
        co.save_data(directory_path + '.pcap', acksize_tcp_dir_exp, acksize_all)
        co.save_data(directory_path + '.pcap', rtt_dir_exp, rtt_all)
        co.save_data(directory_path + '.pcap', stat_dir_exp, connections)
