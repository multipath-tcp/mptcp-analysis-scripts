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
import dpkt
import glob
import os
import shutil
import socket
import subprocess
import sys

##################################################
##                  EXCEPTIONS                  ##
##################################################


class TCPTraceError(Exception):
    pass


class TstatError(Exception):
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
    """ Given a dictionary of TCPConnection, return the smallest start time (0 of relative scale) """
    relative_start = float("inf")
    for conn_id, conn in connections.iteritems():
        start_time = conn.flow.attr[co.START]
        if start_time < relative_start:
            relative_start = start_time
    return relative_start


def extract_tstat_data(pcap_filepath):
    """ Given the pcap filepath, return a dictionary of as many elements as there are tcp flows """
    connections = {}
    conn_id = 0
    with co.cd(os.path.basename(pcap_filepath[:-5])):
        with co.cd(os.listdir('.')[0]):
            # We are interested in the complete TCP connections
            log_file = open('log_tcp_complete')
            data = log_file.readlines()
            for line in data:
                # Case 1: line start with #; skip it
                if not line.startswith("#"):
                    # Case 2: extract info from the line
                    info = line.split()
                    conn_id += 1
                    connection = TCPConnection(conn_id)
                    connection.flow.attr[co.SADDR] = co.long_ipv6_address(info[0])
                    connection.flow.attr[co.DADDR] = co.long_ipv6_address(info[14])
                    connection.flow.attr[co.SPORT] = info[1]
                    connection.flow.attr[co.DPORT] = info[15]
                    connection.flow.detect_ipv4()
                    connection.flow.indicates_wifi_or_cell()
                    # Except RTT, all time (in ms in tstat) shoud be converted into seconds
                    connection.flow.attr[co.START] = float(info[28]) / 1000.0
                    connection.flow.attr[co.DURATION] = float(info[30]) / 1000.0
                    connection.flow.attr[co.S2D][co.PACKS] = int(info[2])
                    connection.flow.attr[co.D2S][co.PACKS] = int(info[16])
                    # Note that this count is about unique data bytes (sent in the payload)
                    connection.flow.attr[co.S2D][co.BYTES] = int(info[6])
                    connection.flow.attr[co.D2S][co.BYTES] = int(info[20])
                    # This is about actual data bytes (sent in the payload, including retransmissions)
                    connection.flow.attr[co.S2D][co.BYTES_DATA] = int(info[8])
                    connection.flow.attr[co.D2S][co.BYTES_DATA] = int(info[22])

                    connection.flow.attr[co.S2D][co.PACKS_RETRANS] = int(info[9])
                    connection.flow.attr[co.D2S][co.PACKS_RETRANS] = int(info[21])
                    connection.flow.attr[co.S2D][co.BYTES_RETRANS] = int(info[10])
                    connection.flow.attr[co.D2S][co.BYTES_RETRANS] = int(info[24])

                    connection.flow.attr[co.S2D][co.PACKS_OOO] = int(info[11])
                    connection.flow.attr[co.D2S][co.PACKS_OOO] = int(info[25])

                    connection.flow.attr[co.S2D][co.NB_SYN] = int(info[12])
                    connection.flow.attr[co.D2S][co.NB_SYN] = int(info[26])
                    connection.flow.attr[co.S2D][co.NB_FIN] = int(info[13])
                    connection.flow.attr[co.D2S][co.NB_FIN] = int(info[27])
                    connection.flow.attr[co.S2D][co.NB_RST] = int(info[3])
                    connection.flow.attr[co.D2S][co.NB_RST] = int(info[17])
                    connection.flow.attr[co.S2D][co.NB_ACK] = int(info[4])
                    connection.flow.attr[co.S2D][co.NB_ACK] = int(info[18])

                    # Except RTT, all time (in ms in tstat) shoud be converted into seconds
                    connection.flow.attr[co.S2D][co.TIME_FIRST_PAYLD] = float(info[31]) / 1000.0
                    connection.flow.attr[co.D2S][co.TIME_FIRST_PAYLD] = float(info[32]) / 1000.0
                    connection.flow.attr[co.S2D][co.TIME_LAST_PAYLD] = float(info[33]) / 1000.0
                    connection.flow.attr[co.D2S][co.TIME_LAST_PAYLD] = float(info[34]) / 1000.0
                    connection.flow.attr[co.S2D][co.TIME_FIRST_ACK] = float(info[36]) / 1000.0
                    connection.flow.attr[co.D2S][co.TIME_FIRST_ACK] = float(info[37]) / 1000.0

                    connection.flow.attr[co.S2D][co.RTT_SAMPLES] = int(info[48])
                    connection.flow.attr[co.D2S][co.RTT_SAMPLES] = int(info[55])
                    connection.flow.attr[co.S2D][co.RTT_MIN] = float(info[45])
                    connection.flow.attr[co.D2S][co.RTT_MIN] = float(info[52])
                    connection.flow.attr[co.S2D][co.RTT_MAX] = float(info[46])
                    connection.flow.attr[co.D2S][co.RTT_MAX] = float(info[53])
                    connection.flow.attr[co.S2D][co.RTT_AVG] = float(info[44])
                    connection.flow.attr[co.D2S][co.RTT_AVG] = float(info[51])
                    connection.flow.attr[co.S2D][co.RTT_STDEV] = float(info[47])
                    connection.flow.attr[co.D2S][co.RTT_STDEV] = float(info[54])
                    connection.flow.attr[co.S2D][co.TTL_MIN] = float(info[49])
                    connection.flow.attr[co.D2S][co.TTL_MIN] = float(info[56])
                    connection.flow.attr[co.S2D][co.TTL_MAX] = float(info[50])
                    connection.flow.attr[co.D2S][co.TTL_MAX] = float(info[57])

                    connection.flow.attr[co.S2D][co.SS_MIN] = int(info[71])
                    connection.flow.attr[co.D2S][co.SS_MIN] = int(info[94])
                    connection.flow.attr[co.S2D][co.SS_MAX] = int(info[70])
                    connection.flow.attr[co.D2S][co.SS_MAX] = int(info[93])

                    connection.flow.attr[co.S2D][co.CWIN_MIN] = int(info[76])
                    connection.flow.attr[co.D2S][co.CWIN_MIN] = int(info[99])
                    connection.flow.attr[co.S2D][co.CWIN_MAX] = int(info[75])
                    connection.flow.attr[co.D2S][co.CWIN_MAX] = int(info[98])

                    connection.flow.attr[co.S2D][co.NB_RTX_RTO] = int(info[78])
                    connection.flow.attr[co.D2S][co.NB_RTX_RTO] = int(info[101])
                    connection.flow.attr[co.S2D][co.NB_RTX_FR] = int(info[79])
                    connection.flow.attr[co.D2S][co.NB_RTX_FR] = int(info[102])
                    connection.flow.attr[co.S2D][co.NB_REORDERING] = int(info[80])
                    connection.flow.attr[co.D2S][co.NB_REORDERING] = int(info[103])
                    connection.flow.attr[co.S2D][co.NB_NET_DUP] = int(info[81])
                    connection.flow.attr[co.D2S][co.NB_NET_DUP] = int(info[104])
                    connection.flow.attr[co.S2D][co.NB_UNKNOWN] = int(info[82])
                    connection.flow.attr[co.D2S][co.NB_UNKNOWN] = int(info[105])
                    connection.flow.attr[co.S2D][co.NB_FLOW_CONTROL] = int(info[83])
                    connection.flow.attr[co.D2S][co.NB_FLOW_CONTROL] = int(info[106])
                    connection.flow.attr[co.S2D][co.NB_UNNECE_RTX_RTO] = int(info[84])
                    connection.flow.attr[co.D2S][co.NB_UNNECE_RTX_RTO] = int(info[107])
                    connection.flow.attr[co.S2D][co.NB_UNNECE_RTX_FR] = int(info[85])
                    connection.flow.attr[co.D2S][co.NB_UNNECE_RTX_FR] = int(info[108])

                    connection.attr[co.S2D][co.BYTES] = {}
                    connection.attr[co.D2S][co.BYTES] = {}

                    connections[conn_id] = connection

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


def process_tstat_cmd(cmd, pcap_filepath, keep_log=False, graph_dir_exp=None):
    """ Launch the command cmd given in argument, and return a dictionary containing information
        about connections of the pcap file analyzed
        Raise a TstatError if tstat encounters problems
    """
    pcap_flow_data_path = pcap_filepath[:-5] + '_tstat'
    stdout_tstat = open(pcap_flow_data_path, 'w+')
    if subprocess.call(cmd, stdout=stdout_tstat) != 0:
        raise TstatError("Error of tcptrace with " + pcap_filepath)

    connections = extract_tstat_data(pcap_filepath)

    # Remove the directory of trace statistics
    shutil.rmtree(os.path.basename(pcap_filepath[:-5]))

    # Don't forget to close and remove pcap_flow_data
    stdout_tstat.close()
    if keep_log:
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
    port = str_data[separator + 1:]
    return ip, port


def get_total_and_retrans_frames(pcap_filepath, connections):
    """ Fill information for connections based on tshark """
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
                if conn.flow.attr[co.SADDR] == ip_src and conn.flow.attr[co.SPORT] == port_src and \
                        conn.flow.attr[co.DADDR] == ip_dst and conn.flow.attr[co.DPORT]:
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
                if conn.flow.attr[co.SADDR] == ip_src and conn.flow.attr[co.SPORT] == port_src and \
                   conn.flow.attr[co.DADDR] == ip_dst and conn.flow.attr[co.DPORT]:
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

##################################################
##                  PROCESSING                  ##
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


def get_flow_name_connection(connection, connections):
    """ Return the connection id and flow id in MPTCP connections of the TCP connection
        Same if same source/dest ip/port
        If not found, return None, None
    """
    for conn_id, conn in connections.iteritems():
        # Let a little margin, but don't think it's needed
        if (connection.flow.attr[co.START] >= conn.attr[co.START] - 120.0 and
                connection.flow.attr[co.START] + connection.flow.attr[co.DURATION] <=
                conn.attr[co.START] + conn.attr[co.DURATION] + 120.0):
            for flow_id, flow in conn.flows.iteritems():
                if (connection.flow.attr[co.SADDR] == flow.attr[co.SADDR] and
                        connection.flow.attr[co.DADDR] == flow.attr[co.DADDR] and
                        connection.flow.attr[co.SPORT] == flow.attr[co.SPORT] and
                        connection.flow.attr[co.DPORT] == flow.attr[co.DPORT]):
                    return conn_id, flow_id

    return None, None


def copy_info_to_mptcp_connections(connections, mptcp_connections, failed_conns, acksize_all, acksize_all_mptcp, flow_name):
    """ Given a tcp connection, copy its start and duration to the corresponding mptcp connection
        If connection is a failed subflow of a MPTCPConnection, add it in failed_conns
        Return the corresponding connection and flow ids of the mptcp connection
    """
    connection = connections[flow_name]
    conn_id, flow_id = get_flow_name_connection(connection, mptcp_connections)
    if isinstance(conn_id, (int, long)):
        mptcp_connections[conn_id].flows[flow_id].subflow_id = flow_name
        mptcp_connections[conn_id].flows[flow_id].attr[co.START] = connection.flow.attr[co.START]
        mptcp_connections[conn_id].flows[flow_id].attr[co.DURATION] = connection.flow.attr[co.DURATION]
        for direction in co.DIRECTIONS:
            for attr in connection.flow.attr[direction]:
                mptcp_connections[conn_id].flows[flow_id].attr[direction][attr] = connection.flow.attr[direction][attr]

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


def retransmissions_tcpcsm(pcap_filepath, connections):
    cmd = ['tcpcsm', '-o', pcap_filepath[:-5] + '_tcpcsm', '-R', pcap_filepath]
    try:
        if subprocess.call(cmd) != 0:
            return
    except Exception as e:
        print(str(e), file=sys.stderr)
        return

    # Create a reversed dictionary to speed up the lookup
    inverse_dict = create_inverse_tcp_dictionary(connections)

    tcpcsm_file = open(pcap_filepath[:-5] + '_tcpcsm')
    data = tcpcsm_file.readlines()
    tcpcsm_file.close()

    for line in data:
        split_line = line.split()
        if split_line[6] in ['RTO', 'FRETX', 'MS_FRETX', 'SACK_FRETX', 'BAD_FRETX', 'LOSS_REC', 'UNEXP_FREC', 'UNNEEDED']:
            key = (split_line[1], split_line[0], split_line[3], split_line[2])
            if len(inverse_dict.get(key, [])) == 1:
                conn_id = inverse_dict[key][0]
                direction = co.S2D if split_line[5] == '1' else co.D2S
                if co.TCPCSM_RETRANS not in connections[conn_id].flow.attr[direction]:
                    connections[conn_id].flow.attr[direction][co.TCPCSM_RETRANS] = [(split_line[7], split_line[6])]
                else:
                    connections[conn_id].flow.attr[direction][co.TCPCSM_RETRANS] += [(split_line[7], split_line[6])]

    os.remove(pcap_filepath[:-5] + '_tcpcsm')


def create_inverse_tcp_dictionary(connections):
    inverse = {}
    for conn_id, conn in connections.iteritems():
        flow = conn.flow
        key = (flow.attr[co.SADDR], flow.attr[co.SPORT], flow.attr[co.DADDR], flow.attr[co.DPORT])
        if key not in inverse:
            inverse[key] = [conn_id]
        else:
            inverse[key] += [conn_id]

    return inverse


def increment_value_dict(dico, key):
    if key in dico:
        dico[key] += 1
    else:
        dico[key] = 1


def compute_tcp_acks(pcap_filepath, connections, inverse_conns, ts_syn_timeout=30.0, ts_timeout=3600.0):
    """ Process a tcp pcap file and returns a dictionary of the number of cases an acknowledgement of x bytes is received """
    print("Computing TCP ack sizes for", pcap_filepath)
    nb_acks = {co.S2D: {}, co.D2S: {}}
    acks = {co.S2D: {}, co.D2S: {}}
    # Avoid processing packets that do not belong to any analyzed TCP connection
    black_list = set()
    pcap_file = open(pcap_filepath)
    pcap = dpkt.pcap.Reader(pcap_file)
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if type(eth.data) == dpkt.ip.IP or type(eth.data) == dpkt.ip6.IP6:
            ip = eth.data
            if type(ip.data) == dpkt.tcp.TCP:
                tcp = ip.data
                fin_flag = (tcp.flags & dpkt.tcp.TH_FIN) != 0
                syn_flag = (tcp.flags & dpkt.tcp.TH_SYN) != 0
                rst_flag = (tcp.flags & dpkt.tcp.TH_RST) != 0
                ack_flag = (tcp.flags & dpkt.tcp.TH_ACK) != 0

                # For IP addresses, need to convert the packet IP address to the standard one
                if type(eth.data) == dpkt.ip.IP:
                    daddr = socket.inet_ntop(socket.AF_INET, ip.dst)
                    saddr = socket.inet_ntop(socket.AF_INET, ip.src)
                else:  # dpkt.ip6.IP6
                    daddr = socket.inet_ntop(socket.AF_INET6, ip.dst)
                    saddr = socket.inet_ntop(socket.AF_INET6, ip.src)
                # Ports encoded as strings in connections, so let convert those integers
                dport = str(tcp.dport)
                sport = str(tcp.sport)

                if syn_flag and not ack_flag and not fin_flag and not rst_flag:
                    # The sender of the first SYN is the client
                    # Check if the connection is black listed or not
                    conn_id = False
                    conn_candidates = inverse_conns.get((saddr, sport, daddr, dport), [])
                    for cid in conn_candidates:
                        if abs(ts - connections[cid].flow.attr[co.START]) < ts_syn_timeout:
                            conn_id = cid
                            break

                    if not conn_id:
                        black_list.add((saddr, sport, daddr, dport))
                        continue
                    elif conn_id and (saddr, sport, daddr, dport) in black_list:
                        black_list.remove((saddr, sport, daddr, dport))

                    if conn_id not in nb_acks[co.S2D]:
                        for direction in co.DIRECTIONS:
                            nb_acks[direction][conn_id] = {}

                    if (saddr, sport, daddr, dport) in acks:
                        # Already taken, but maybe old, such that we can overwrite it (show on screen the TS difference)
                        print(saddr, sport, daddr, dport, "already used; it was (in seconds)", ts - acks[saddr, sport, daddr, dport][co.TIMESTAMP])
                    acks[saddr, sport, daddr, dport] = {co.S2D: -1, co.D2S: -1, co.TIMESTAMP: ts, co.CONN_ID: conn_id}

                elif (saddr, sport, daddr, dport) in black_list:
                    continue

                elif syn_flag and ack_flag and not fin_flag and not rst_flag:
                    # The sender of the SYN/ACK is the server
                    if (daddr, dport, saddr, sport) in acks and ts - acks[daddr, dport, saddr, sport][co.TIMESTAMP] < ts_timeout:
                        # Better to check, if not seen, maybe uncomplete TCP connection
                        acks[daddr, dport, saddr, sport][co.S2D] = tcp.ack

                elif not syn_flag and not rst_flag and ack_flag:
                    if (saddr, sport, daddr, dport) in acks:
                        if acks[saddr, sport, daddr, dport][co.D2S] >= 0:
                            bytes_acked = (tcp.ack - acks[saddr, sport, daddr, dport][co.D2S]) % 4294967296
                            if bytes_acked >= 2000000000:
                                # Ack of 2GB or more is just not possible here
                                continue
                            conn_id = acks[saddr, sport, daddr, dport][co.CONN_ID]
                            increment_value_dict(nb_acks[co.D2S][conn_id], bytes_acked)
                        acks[saddr, sport, daddr, dport][co.D2S] = tcp.ack
                    elif (daddr, dport, saddr, sport) in acks:
                        if acks[daddr, dport, saddr, sport][co.S2D] >= 0:
                            bytes_acked = (tcp.ack - acks[daddr, dport, saddr, sport][co.S2D]) % 4294967296
                            if bytes_acked >= 2000000000:
                                # Ack of 2GB or more is just not possible here
                                continue
                            conn_id = acks[daddr, dport, saddr, sport][co.CONN_ID]
                            increment_value_dict(nb_acks[co.S2D][conn_id], bytes_acked)
                        acks[daddr, dport, saddr, sport][co.S2D] = tcp.ack
                    else:
                        # Silently ignore those packets
                        # print(saddr, sport, daddr, dport, "haven't seen beginning...")
                        continue

    return nb_acks


def process_trace(pcap_filepath, graph_dir_exp, stat_dir_exp, failed_conns_dir_exp, acksize_tcp_dir_exp, tcpcsm, mptcp_connections=None, print_out=sys.stdout):
    """ Process a tcp pcap file and generate stats of its connections """
    cmd = ['tstat', '-s', os.path.basename(pcap_filepath[:-5]), pcap_filepath]

    try:
        connections = process_tstat_cmd(cmd, pcap_filepath, keep_log=True, graph_dir_exp=graph_dir_exp)
    except TstatError as e:
        print(str(e) + ": skip process", file=sys.stderr)
        return

    # Directory containing all TCPConnections that tried to be MPTCP subflows, but failed to
    failed_conns = {}

    if tcpcsm:
        retransmissions_tcpcsm(pcap_filepath, connections)

    inverse_conns = create_inverse_tcp_dictionary(connections)

    acksize_all = compute_tcp_acks(pcap_filepath, connections, inverse_conns)
    acksize_all_mptcp = {co.S2D: {}, co.D2S: {}}

    if mptcp_connections:
        for flow_id in connections:
            # Copy info to mptcp connections
            copy_info_to_mptcp_connections(connections, mptcp_connections, failed_conns, acksize_all, acksize_all_mptcp, flow_id)

    # Save connections info
    if mptcp_connections:
        co.save_data(pcap_filepath, acksize_tcp_dir_exp, acksize_all_mptcp)
        # Also save TCP connections that failed to be MPTCP subflows
        co.save_data(pcap_filepath, failed_conns_dir_exp, failed_conns)
    else:
        co.save_data(pcap_filepath, acksize_tcp_dir_exp, acksize_all)
        co.save_data(pcap_filepath, stat_dir_exp, connections)
