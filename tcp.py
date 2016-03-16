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
# from collections import deque

##################################################
#                    IMPORTS                     #
##################################################

from datetime import timedelta

import bisect
import common as co
import dpkt
import glob
import os
import shutil
import socket
import socks_parser
import subprocess
import sys

##################################################
#                   EXCEPTIONS                   #
##################################################


class TstatError(Exception):
    pass


##################################################
#          GLOBAL VARIABLES FOR WARNING          #
##################################################

dss_not_ack_warning = False

##################################################
#                 CONSTANTS                      #
##################################################

SEQ_C2S = 'seq_c2s'
SEQ_S2C = 'seq_s2c'
HSEQ_C2S = 'hseq_c2s'
HSEQ_S2C = 'hseq_s2c'
CLIENT = 'client'
SERVER = 'server'

##################################################
#            CONNECTION DATA RELATED             #
##################################################


class TCPConnection(co.BasicConnection):

    """ Represent a TCP connection """
    flow = None

    def __init__(self, conn_id):
        super(TCPConnection, self).__init__(conn_id)
        self.flow = co.BasicFlow()


def extract_tstat_data_tcp_complete(filename, connections, conn_id):
    """ Subpart of extract_tstat_data dedicated to the processing of the log_tcp_complete file
        Returns the connections seen and the conn_id reached
    """
    log_file = open(filename)
    data = log_file.readlines()
    for line in data:
        # Case 1: line start with #; skip it
        if not line.startswith("#"):
            # Case 2: extract info from the line
            info = line.split()
            conn_id += 1
            connection = TCPConnection(conn_id)
            connection.flow.attr[co.TCP_COMPLETE] = True
            connection.flow.attr[co.SADDR] = co.long_ipv6_address(info[0])
            connection.flow.attr[co.DADDR] = co.long_ipv6_address(info[14])
            connection.flow.attr[co.SPORT] = info[1]
            connection.flow.attr[co.DPORT] = info[15]
            connection.flow.detect_ipv4()
            connection.flow.indicates_wifi_or_cell()
            # Except RTT, all time (in ms in tstat) shoud be converted into seconds
            connection.flow.attr[co.START] = timedelta(seconds=float(info[28])/1000)
            connection.flow.attr[co.DURATION] = float(info[30]) / 1000.0
            connection.flow.attr[co.C2S][co.PACKS] = int(info[2])
            connection.flow.attr[co.S2C][co.PACKS] = int(info[16])
            # Note that this count is about unique data bytes (sent in the payload)
            connection.flow.attr[co.C2S][co.BYTES] = int(info[6])
            connection.flow.attr[co.S2C][co.BYTES] = int(info[20])
            # This is about actual data bytes (sent in the payload, including retransmissions)
            connection.flow.attr[co.C2S][co.BYTES_DATA] = int(info[8])
            connection.flow.attr[co.S2C][co.BYTES_DATA] = int(info[22])

            connection.flow.attr[co.C2S][co.PACKS_RETRANS] = int(info[9])
            connection.flow.attr[co.S2C][co.PACKS_RETRANS] = int(info[23])
            connection.flow.attr[co.C2S][co.BYTES_RETRANS] = int(info[10])
            connection.flow.attr[co.S2C][co.BYTES_RETRANS] = int(info[24])

            connection.flow.attr[co.C2S][co.PACKS_OOO] = int(info[11])
            connection.flow.attr[co.S2C][co.PACKS_OOO] = int(info[25])

            connection.flow.attr[co.C2S][co.NB_SYN] = int(info[12])
            connection.flow.attr[co.S2C][co.NB_SYN] = int(info[26])
            connection.flow.attr[co.C2S][co.NB_FIN] = int(info[13])
            connection.flow.attr[co.S2C][co.NB_FIN] = int(info[27])
            connection.flow.attr[co.C2S][co.NB_RST] = int(info[3])
            connection.flow.attr[co.S2C][co.NB_RST] = int(info[17])
            connection.flow.attr[co.C2S][co.NB_ACK] = int(info[4])
            connection.flow.attr[co.S2C][co.NB_ACK] = int(info[18])

            # Except RTT, all time (in ms in tstat) shoud be converted into seconds
            connection.flow.attr[co.C2S][co.TIME_FIRST_PAYLD] = float(info[31]) / 1000.0
            connection.flow.attr[co.S2C][co.TIME_FIRST_PAYLD] = float(info[32]) / 1000.0
            connection.flow.attr[co.C2S][co.TIME_LAST_PAYLD] = float(info[33]) / 1000.0
            connection.flow.attr[co.S2C][co.TIME_LAST_PAYLD] = float(info[34]) / 1000.0
            connection.flow.attr[co.C2S][co.TIME_FIRST_ACK] = float(info[35]) / 1000.0
            connection.flow.attr[co.S2C][co.TIME_FIRST_ACK] = float(info[36]) / 1000.0

            connection.flow.attr[co.C2S][co.RTT_SAMPLES] = int(info[48])
            connection.flow.attr[co.S2C][co.RTT_SAMPLES] = int(info[55])
            connection.flow.attr[co.C2S][co.RTT_MIN] = float(info[45])
            connection.flow.attr[co.S2C][co.RTT_MIN] = float(info[52])
            connection.flow.attr[co.C2S][co.RTT_MAX] = float(info[46])
            connection.flow.attr[co.S2C][co.RTT_MAX] = float(info[53])
            connection.flow.attr[co.C2S][co.RTT_AVG] = float(info[44])
            connection.flow.attr[co.S2C][co.RTT_AVG] = float(info[51])
            connection.flow.attr[co.C2S][co.RTT_STDEV] = float(info[47])
            connection.flow.attr[co.S2C][co.RTT_STDEV] = float(info[54])
            connection.flow.attr[co.C2S][co.TTL_MIN] = float(info[49])
            connection.flow.attr[co.S2C][co.TTL_MIN] = float(info[56])
            connection.flow.attr[co.C2S][co.TTL_MAX] = float(info[50])
            connection.flow.attr[co.S2C][co.TTL_MAX] = float(info[57])

            connection.flow.attr[co.C2S][co.SS_MIN] = int(info[71])
            connection.flow.attr[co.S2C][co.SS_MIN] = int(info[94])
            connection.flow.attr[co.C2S][co.SS_MAX] = int(info[70])
            connection.flow.attr[co.S2C][co.SS_MAX] = int(info[93])

            connection.flow.attr[co.C2S][co.CWIN_MIN] = int(info[76])
            connection.flow.attr[co.S2C][co.CWIN_MIN] = int(info[99])
            connection.flow.attr[co.C2S][co.CWIN_MAX] = int(info[75])
            connection.flow.attr[co.S2C][co.CWIN_MAX] = int(info[98])

            connection.flow.attr[co.C2S][co.NB_RTX_RTO] = int(info[78])
            connection.flow.attr[co.S2C][co.NB_RTX_RTO] = int(info[101])
            connection.flow.attr[co.C2S][co.NB_RTX_FR] = int(info[79])
            connection.flow.attr[co.S2C][co.NB_RTX_FR] = int(info[102])
            connection.flow.attr[co.C2S][co.NB_REORDERING] = int(info[80])
            connection.flow.attr[co.S2C][co.NB_REORDERING] = int(info[103])
            connection.flow.attr[co.C2S][co.NB_NET_DUP] = int(info[81])
            connection.flow.attr[co.S2C][co.NB_NET_DUP] = int(info[104])
            connection.flow.attr[co.C2S][co.NB_UNKNOWN] = int(info[82])
            connection.flow.attr[co.S2C][co.NB_UNKNOWN] = int(info[105])
            connection.flow.attr[co.C2S][co.NB_FLOW_CONTROL] = int(info[83])
            connection.flow.attr[co.S2C][co.NB_FLOW_CONTROL] = int(info[106])
            connection.flow.attr[co.C2S][co.NB_UNNECE_RTX_RTO] = int(info[84])
            connection.flow.attr[co.S2C][co.NB_UNNECE_RTX_RTO] = int(info[107])
            connection.flow.attr[co.C2S][co.NB_UNNECE_RTX_FR] = int(info[85])
            connection.flow.attr[co.S2C][co.NB_UNNECE_RTX_FR] = int(info[108])

            connection.attr[co.C2S][co.BYTES] = {}
            connection.attr[co.S2C][co.BYTES] = {}

            connection.flow.attr[co.C2S][co.TIMESTAMP_RETRANS] = []
            connection.flow.attr[co.S2C][co.TIMESTAMP_RETRANS] = []

            connection.flow.attr[co.C2S][co.TIME_FIN_ACK_TCP] = timedelta(0)
            connection.flow.attr[co.S2C][co.TIME_FIN_ACK_TCP] = timedelta(0)

            connection.flow.attr[co.C2S][co.TIME_LAST_ACK_TCP] = timedelta(0)
            connection.flow.attr[co.S2C][co.TIME_LAST_ACK_TCP] = timedelta(0)

            connection.flow.attr[co.C2S][co.TIME_LAST_PAYLD_TCP] = timedelta(0)
            connection.flow.attr[co.S2C][co.TIME_LAST_PAYLD_TCP] = timedelta(0)

            connection.flow.attr[co.C2S][co.TIME_LAST_PAYLD_WITH_RETRANS_TCP] = timedelta(0)
            connection.flow.attr[co.S2C][co.TIME_LAST_PAYLD_WITH_RETRANS_TCP] = timedelta(0)

            connections[conn_id] = connection

    log_file.close()
    return connections, conn_id


def extract_tstat_data_tcp_nocomplete(filename, connections, conn_id):
    log_file = open(filename)
    data = log_file.readlines()
    for line in data:
        # Case 1: line start with #; skip it
        if not line.startswith("#"):
            # Case 2: extract info from the line
            info = line.split()
            conn_id += 1
            connection = TCPConnection(conn_id)

            connection.flow.attr[co.TCP_COMPLETE] = False

            connection.flow.attr[co.SADDR] = co.long_ipv6_address(info[0])
            connection.flow.attr[co.DADDR] = co.long_ipv6_address(info[14])
            connection.flow.attr[co.SPORT] = info[1]
            connection.flow.attr[co.DPORT] = info[15]

            connection.flow.detect_ipv4()
            connection.flow.indicates_wifi_or_cell()
            # Except RTT, all time (in ms in tstat) shoud be converted into seconds
            connection.flow.attr[co.START] = timedelta(seconds=float(info[28])/1000)
            connection.flow.attr[co.DURATION] = float(info[30]) / 1000.0
            connection.flow.attr[co.C2S][co.PACKS] = int(info[2])
            connection.flow.attr[co.S2C][co.PACKS] = int(info[16])
            # Note that this count is about unique data bytes (sent in the payload)
            connection.flow.attr[co.C2S][co.BYTES] = int(info[6])
            connection.flow.attr[co.S2C][co.BYTES] = int(info[20])
            # This is about actual data bytes (sent in the payload, including retransmissions)
            connection.flow.attr[co.C2S][co.BYTES_DATA] = int(info[8])
            connection.flow.attr[co.S2C][co.BYTES_DATA] = int(info[22])

            connection.flow.attr[co.C2S][co.PACKS_RETRANS] = int(info[9])
            connection.flow.attr[co.S2C][co.PACKS_RETRANS] = int(info[23])
            connection.flow.attr[co.C2S][co.BYTES_RETRANS] = int(info[10])
            connection.flow.attr[co.S2C][co.BYTES_RETRANS] = int(info[24])

            connection.flow.attr[co.C2S][co.PACKS_OOO] = int(info[11])
            connection.flow.attr[co.S2C][co.PACKS_OOO] = int(info[25])

            connection.flow.attr[co.C2S][co.NB_SYN] = int(info[12])
            connection.flow.attr[co.S2C][co.NB_SYN] = int(info[26])
            connection.flow.attr[co.C2S][co.NB_FIN] = int(info[13])
            connection.flow.attr[co.S2C][co.NB_FIN] = int(info[27])
            connection.flow.attr[co.C2S][co.NB_RST] = int(info[3])
            connection.flow.attr[co.S2C][co.NB_RST] = int(info[17])
            connection.flow.attr[co.C2S][co.NB_ACK] = int(info[4])
            connection.flow.attr[co.S2C][co.NB_ACK] = int(info[18])

            # Except RTT, all time (in ms in tstat) shoud be converted into seconds
            connection.flow.attr[co.C2S][co.TIME_FIRST_PAYLD] = float(info[31]) / 1000.0
            connection.flow.attr[co.S2C][co.TIME_FIRST_PAYLD] = float(info[32]) / 1000.0
            connection.flow.attr[co.C2S][co.TIME_LAST_PAYLD] = float(info[33]) / 1000.0
            connection.flow.attr[co.S2C][co.TIME_LAST_PAYLD] = float(info[34]) / 1000.0
            connection.flow.attr[co.C2S][co.TIME_FIRST_ACK] = float(info[35]) / 1000.0
            connection.flow.attr[co.S2C][co.TIME_FIRST_ACK] = float(info[36]) / 1000.0

            connection.attr[co.C2S][co.BYTES] = {}
            connection.attr[co.S2C][co.BYTES] = {}

            connection.flow.attr[co.C2S][co.TIMESTAMP_RETRANS] = []
            connection.flow.attr[co.S2C][co.TIMESTAMP_RETRANS] = []

            connection.flow.attr[co.C2S][co.TIME_FIN_ACK_TCP] = timedelta(0)
            connection.flow.attr[co.S2C][co.TIME_FIN_ACK_TCP] = timedelta(0)

            connection.flow.attr[co.C2S][co.TIME_LAST_ACK_TCP] = timedelta(0)
            connection.flow.attr[co.S2C][co.TIME_LAST_ACK_TCP] = timedelta(0)

            connection.flow.attr[co.C2S][co.TIME_LAST_PAYLD_TCP] = timedelta(0)
            connection.flow.attr[co.S2C][co.TIME_LAST_PAYLD_TCP] = timedelta(0)

            connection.flow.attr[co.C2S][co.TIME_LAST_PAYLD_WITH_RETRANS_TCP] = timedelta(0)
            connection.flow.attr[co.S2C][co.TIME_LAST_PAYLD_WITH_RETRANS_TCP] = timedelta(0)

            connections[conn_id] = connection

    log_file.close()
    return connections, conn_id


def extract_tstat_data(pcap_filepath):
    """ Given the pcap filepath, return a dictionary of as many elements as there are tcp flows """
    connections = {}
    conn_id = 0
    with co.cd(os.path.basename(pcap_filepath[:-5])):
        with co.cd(os.listdir('.')[0]):
            # Complete TCP connections
            connections, conn_id = extract_tstat_data_tcp_complete('log_tcp_complete', connections, conn_id)
            # Non complete TCP connections (less info, but still interesting data)
            connections, conn_id = extract_tstat_data_tcp_nocomplete('log_tcp_nocomplete', connections, conn_id)

    return connections

##################################################
#         CONNECTION IDENTIFIER RELATED          #
##################################################


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
#                    TCPTRACE                    #
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
#                 RETRANSMISSION                 #
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
                    connections[conn_id].flow.attr[co.S2C][co.FRAMES_TOTAL] = int(split_line[3])
                    connections[conn_id].flow.attr[co.S2C][co.BYTES_FRAMES_TOTAL] = int(split_line[4])
                    connections[conn_id].flow.attr[co.C2S][co.FRAMES_TOTAL] = int(split_line[5])
                    connections[conn_id].flow.attr[co.C2S][co.BYTES_FRAMES_TOTAL] = int(split_line[6])
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
                    connections[conn_id].flow.attr[co.S2C][co.FRAMES_RETRANS] = int(split_line[3])
                    connections[conn_id].flow.attr[co.S2C][co.BYTES_FRAMES_RETRANS] = int(split_line[4])
                    connections[conn_id].flow.attr[co.C2S][co.FRAMES_RETRANS] = int(split_line[5])
                    connections[conn_id].flow.attr[co.C2S][co.BYTES_FRAMES_RETRANS] = int(split_line[6])
                    break

    stats_file.close()
    os.remove(stats_filename)

##################################################
#                   PROCESSING                   #
##################################################


def get_preprocessed_connections(connections):
    """ Prepare a dictionary for fast association of a TCP connection with a MPTCP flow """
    fast_dico = {}

    # Collect all potential subflows
    for conn_id, conn in connections.iteritems():
        if conn.attr.get(co.START, None):
            for flow_id, flow in conn.flows.iteritems():
                if (flow.attr[co.SADDR], flow.attr[co.DADDR], flow.attr[co.SPORT], flow.attr[co.DPORT]) not in fast_dico:
                    fast_dico[(flow.attr[co.SADDR], flow.attr[co.DADDR], flow.attr[co.SPORT], flow.attr[co.DPORT])] = []

                fast_dico[(flow.attr[co.SADDR], flow.attr[co.DADDR], flow.attr[co.SPORT], flow.attr[co.DPORT])] += [(conn.attr[co.START],
                                                                                                                     float(conn.attr[co.DURATION]),
                                                                                                                     conn_id, flow_id)]

    # Sort them for faster processing
    for quadruplet in fast_dico.keys():
        fast_dico[quadruplet] = sorted(fast_dico[quadruplet], key=lambda x: x[0])

    return fast_dico


def get_flow_name_connection(connection, connections):
    """ Return the connection id and flow id in MPTCP connections of the TCP connection
        Same if same source/dest ip/port
        If not found, return None, None
    """
    for conn_id, conn in connections.iteritems():
        # Let a little margin, but don't think it's needed
        if conn.attr.get(co.START, None) and (abs((connection.flow.attr[co.START] - conn.attr[co.START]).total_seconds()) <= 8.0 and
                                              connection.flow.attr[co.START].total_seconds() <=
                                              conn.attr[co.START].total_seconds() + float(conn.attr[co.DURATION])):
            for flow_id, flow in conn.flows.iteritems():
                if (connection.flow.attr[co.SADDR] == flow.attr[co.SADDR] and
                        connection.flow.attr[co.DADDR] == flow.attr[co.DADDR] and
                        connection.flow.attr[co.SPORT] == flow.attr[co.SPORT] and
                        connection.flow.attr[co.DPORT] == flow.attr[co.DPORT]):
                    return conn_id, flow_id

    return None, None


def get_flow_name_connection_optimized(connection, connections, fast_conns=None):
    """ Return the connection id and flow id in MPTCP connections of the TCP connection
        Same if same source/dest ip/port
        If not found, return None, None
    """
    if not fast_conns:
        return get_flow_name_connection(connection, connections)

    if (connection.flow.attr[co.SADDR], connection.flow.attr[co.DADDR], connection.flow.attr[co.SPORT], connection.flow.attr[co.DPORT]) in fast_conns:
        potential_list = fast_conns[(connection.flow.attr[co.SADDR], connection.flow.attr[co.DADDR], connection.flow.attr[co.SPORT],
                                    connection.flow.attr[co.DPORT])]

        if len(potential_list) == 1:
            return potential_list[0][2], potential_list[0][3]

        # Search on list
        potential_match_index = 0
        match_indexes = []
        # Check with an error window of 8 seconds for both sides
        while (potential_match_index < len(potential_list)
               and abs((potential_list[potential_match_index][0] - connection.flow.attr[co.START]).total_seconds()) <= 8.0):
            if connection.flow.attr[co.START].total_seconds() <= potential_list[potential_match_index][0].total_seconds() + potential_list[potential_match_index][1]:
                match_indexes += [potential_match_index]

            potential_match_index += 1

        if len(match_indexes) == 1:
            return potential_list[match_indexes[0]][2], potential_list[match_indexes[0]][3]
        elif len(match_indexes) > 1:
            print("More than one possible match...")
            # By default, return the first match
            return potential_list[match_indexes[0]][2], potential_list[match_indexes[0]][3]
        else:
            print("No match found for MPTCP subflow...")

    return None, None


def copy_info_to_mptcp_connections(connections, mptcp_connections, failed_conns, acksize_all, acksize_all_mptcp, flow_name, fast_conns=None):
    """ Given a tcp connection, copy its start and duration to the corresponding mptcp connection
        If connection is a failed subflow of a MPTCPConnection, add it in failed_conns
        Return the corresponding connection and flow ids of the mptcp connection
    """
    connection = connections[flow_name]
    conn_id, flow_id = get_flow_name_connection_optimized(connection, mptcp_connections, fast_conns=fast_conns)
    if isinstance(conn_id, (int, long)):
        mptcp_connections[conn_id].flows[flow_id].subflow_id = flow_name
        mptcp_connections[conn_id].flows[flow_id].attr[co.TCP_COMPLETE] = connection.flow.attr[co.TCP_COMPLETE]
        mptcp_connections[conn_id].flows[flow_id].attr[co.START] = connection.flow.attr[co.START]
        mptcp_connections[conn_id].flows[flow_id].attr[co.DURATION] = connection.flow.attr[co.DURATION]
        if co.BACKUP in connection.attr:
            mptcp_connections[conn_id].flows[flow_id].attr[co.BACKUP] = connection.attr[co.BACKUP]
        if co.SOCKS_PORT in connection.attr:
            mptcp_connections[conn_id].flows[flow_id].attr[co.SOCKS_PORT] = connection.attr[co.SOCKS_PORT]
            mptcp_connections[conn_id].flows[flow_id].attr[co.SOCKS_DADDR] = connection.attr[co.SOCKS_DADDR]
            if co.SOCKS_PORT not in mptcp_connections[conn_id].attr:
                mptcp_connections[conn_id].attr[co.SOCKS_PORT] = connection.attr[co.SOCKS_PORT]
                mptcp_connections[conn_id].attr[co.SOCKS_DADDR] = connection.attr[co.SOCKS_DADDR]

            elif not mptcp_connections[conn_id].attr[co.SOCKS_PORT] == connection.attr[co.SOCKS_PORT] or not mptcp_connections[conn_id].attr[co.SOCKS_DADDR] == connection.attr[co.SOCKS_DADDR]:
                print("DIFFERENT SOCKS PORT...", mptcp_connections[conn_id].attr[co.SOCKS_PORT], connection.attr[co.SOCKS_PORT], mptcp_connections[conn_id].attr[co.SOCKS_DADDR], connection.attr[co.SOCKS_DADDR], conn_id, flow_id)

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
                direction = co.C2S if split_line[5] == '1' else co.S2C
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


def get_ts_delta(ts):
    """ Get a timedelta object for the timestamp """
    if isinstance(ts, tuple) and len(ts) == 2:
        return timedelta(seconds=ts[0], microseconds=ts[1])
    else:
        # Kept for compatibility reasons
        return timedelta(seconds=ts)


def get_ips_and_ports(eth, ip, tcp):
    """ Given the Ethernet (and its conversion in IP) and TCP packet,
        return the IPs and ports of source (client) and destination (server)
    """
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

    return saddr, daddr, sport, dport


def detect_backup_subflow(tcp):
    """ Return True if this subflow is established with the backup bit """
    backup = False
    opt_list = dpkt.tcp.parse_opts(tcp.opts)
    for option_num, option_content in opt_list:
        # Only interested in MPTCP with JOIN (len of 10 because join has len of 12 with 1 of option num and 1 of length)
        if option_num == 30 and len(option_content):
            # Join + backup bit
            if ord(option_content[0]) == 17:
                backup = True

    return backup


def process_first_syn(ts_delta, acks, nb_acks, connections, tcp, ip, saddr, daddr, sport, dport, black_list, inverse_conns, ts_syn_timeout, ts_timeout):
    """ Processing of the first SYNs seen on a connection """
    # The sender of the first SYN is the client
    # Check if the connection is black listed or not
    conn_id = False
    conn_candidates = inverse_conns.get((saddr, sport, daddr, dport), [])
    min_delta = ts_syn_timeout
    for cid in conn_candidates:
        if abs((ts_delta - connections[cid].flow.attr[co.START]).total_seconds()) < min_delta:
            conn_id = cid
            min_delta = abs((ts_delta - connections[cid].flow.attr[co.START]).total_seconds())

    if not conn_id:
        black_list.add((saddr, sport, daddr, dport))
        return
    elif conn_id and (saddr, sport, daddr, dport) in black_list:
        black_list.remove((saddr, sport, daddr, dport))

    if conn_id not in nb_acks[co.C2S]:
        for direction in co.DIRECTIONS:
            nb_acks[direction][conn_id] = {}

    backup = detect_backup_subflow(tcp)

    if ((saddr, sport, daddr, dport) in acks and (ts_delta - acks[saddr, sport, daddr, dport][co.TIMESTAMP][CLIENT]).total_seconds() <= ts_syn_timeout
            and acks[saddr, sport, daddr, dport][co.S2C] == -1 and tcp.seq in acks[saddr, sport, daddr, dport][SEQ_C2S]):
        # SYN retransmission!
        connections[conn_id].flow.attr[co.C2S][co.TIMESTAMP_RETRANS].append((ts_delta,
                                                                             ts_delta - acks[saddr, sport, daddr, dport][HSEQ_C2S][tcp.seq][0],
                                                                             ts_delta - acks[saddr, sport, daddr, dport][HSEQ_C2S][tcp.seq][1],
                                                                             ts_delta - acks[saddr, sport, daddr, dport][co.TIMESTAMP][CLIENT]))
        acks[saddr, sport, daddr, dport][HSEQ_C2S][tcp.seq][1] = ts_delta
    else:
        acks[saddr, sport, daddr, dport] = {co.C2S: -1, co.S2C: -1, co.TIMESTAMP: {CLIENT: ts_delta, SERVER: None}, co.CONN_ID: conn_id,
                                            SEQ_C2S: set([tcp.seq]), SEQ_S2C: set([]), HSEQ_C2S: {tcp.seq: [ts_delta, ts_delta]}, HSEQ_S2C: {}}
        connections[conn_id].attr[co.BACKUP] = backup


def process_syn_ack(ts_delta, acks, nb_acks, connections, tcp, ip, saddr, daddr, sport, dport, black_list, inverse_conns, ts_syn_timeout, ts_timeout):
    """ Processing of SYN/ACKs seen on the connection """
    # The sender of the SYN/ACK is the server
    if (daddr, dport, saddr, sport) in acks and ((ts_delta - acks[daddr, dport, saddr, sport][co.TIMESTAMP][CLIENT]).total_seconds() < ts_timeout
                                                 and acks[daddr, dport, saddr, sport][co.C2S] == -1):
        # Better to check, if not seen, maybe uncomplete TCP connection
        acks[daddr, dport, saddr, sport][co.C2S] = tcp.ack
        acks[daddr, dport, saddr, sport][SEQ_S2C].add(tcp.seq)
        acks[daddr, dport, saddr, sport][HSEQ_S2C][tcp.seq] = [ts_delta, ts_delta]
        acks[daddr, dport, saddr, sport][co.TIMESTAMP][SERVER] = ts_delta

    elif (daddr, dport, saddr, sport) in acks and ((ts_delta - acks[daddr, dport, saddr, sport][co.TIMESTAMP][CLIENT]).total_seconds() < ts_timeout
                                                   and tcp.seq in acks[daddr, dport, saddr, sport][SEQ_S2C]):
        # SYN/ACK retransmission!
        conn_id = acks[daddr, dport, saddr, sport][co.CONN_ID]
        connections[conn_id].flow.attr[co.S2C][co.TIMESTAMP_RETRANS].append((ts_delta,
                                                                             ts_delta - acks[daddr, dport, saddr, sport][HSEQ_S2C][tcp.seq][0],
                                                                             ts_delta - acks[daddr, dport, saddr, sport][HSEQ_S2C][tcp.seq][1],
                                                                             ts_delta - acks[daddr, dport, saddr, sport][co.TIMESTAMP][CLIENT]))
        acks[daddr, dport, saddr, sport][HSEQ_S2C][tcp.seq][1] = ts_delta
        acks[daddr, dport, saddr, sport][co.TIMESTAMP][SERVER] = ts_delta


def process_pkt_from_client(ts_delta, acks, nb_acks, connections, tcp, ip, saddr, daddr, sport, dport, fin_flag):
    """ Process a packet with ACK set from the client """
    if acks[saddr, sport, daddr, dport][co.S2C] >= 0:
        conn_id = acks[saddr, sport, daddr, dport][co.CONN_ID]
        connections[conn_id].flow.attr[co.S2C][co.TIME_LAST_ACK_TCP] = ts_delta
        if fin_flag:
            connections[conn_id].flow.attr[co.S2C][co.TIME_FIN_ACK_TCP] = ts_delta

        bytes_acked = (tcp.ack - acks[saddr, sport, daddr, dport][co.S2C]) % 4294967296
        if bytes_acked >= 2000000000:
            # Ack of 2GB or more is just not possible here
            return

        increment_value_dict(nb_acks[co.S2C][conn_id], bytes_acked)
        size_payload = ip.len - ip.hl * 4 - tcp.off * 4

        # If SOCKS command
        if size_payload == 7 and connections[conn_id].attr.get(co.SOCKS_PORT, None) is None:
            crypted_socks_cmd = tcp.data
            # This is possible because of packet stripping
            if len(crypted_socks_cmd) == 7:
                decrypted_socks_cmd = socks_parser.decode(crypted_socks_cmd)
                if decrypted_socks_cmd[0] == b'\x01':  # Connect
                    connections[conn_id].attr[co.SOCKS_DADDR] = socks_parser.get_ip_address(decrypted_socks_cmd)
                    connections[conn_id].attr[co.SOCKS_PORT] = socks_parser.get_port_number(decrypted_socks_cmd)

        if size_payload > 0 and tcp.seq in acks[saddr, sport, daddr, dport][SEQ_C2S]:
            # This is a retransmission! (take into account the seq overflow)
            connections[conn_id].flow.attr[co.C2S][co.TIME_LAST_PAYLD_WITH_RETRANS_TCP] = ts_delta
            connections[conn_id].flow.attr[co.C2S][co.TIMESTAMP_RETRANS].append((ts_delta,
                                                                                 ts_delta - acks[saddr, sport, daddr, dport][HSEQ_C2S][tcp.seq][0],
                                                                                 ts_delta - acks[saddr, sport, daddr, dport][HSEQ_C2S][tcp.seq][1],
                                                                                 ts_delta - acks[saddr, sport, daddr, dport][co.TIMESTAMP][CLIENT]))
            acks[saddr, sport, daddr, dport][HSEQ_C2S][tcp.seq][1] = ts_delta
        elif size_payload > 0:
            acks[saddr, sport, daddr, dport][SEQ_C2S].add(tcp.seq)
            connections[conn_id].flow.attr[co.C2S][co.TIME_LAST_PAYLD_WITH_RETRANS_TCP] = ts_delta
            connections[conn_id].flow.attr[co.C2S][co.TIME_LAST_PAYLD_TCP] = ts_delta
            acks[saddr, sport, daddr, dport][HSEQ_C2S][tcp.seq] = [ts_delta, ts_delta]
            # Don't think will face this issue
#                                 if len(acks[saddr, sport, daddr, dport][SEQ][co.C2S]) >= 3000000:
#                                     for x in range(50000):
#                                         acks[saddr, sport, daddr, dport][SEQ][co.C2S].popleft()

    acks[saddr, sport, daddr, dport][co.S2C] = tcp.ack
    acks[saddr, sport, daddr, dport][co.TIMESTAMP][CLIENT] = ts_delta


def process_pkt_from_server(ts_delta, acks, nb_acks, connections, tcp, ip, saddr, daddr, sport, dport, fin_flag):
    """ Process a packet with ACK set from the server """
    if acks[daddr, dport, saddr, sport][co.C2S] >= 0:
        conn_id = acks[daddr, dport, saddr, sport][co.CONN_ID]
        connections[conn_id].flow.attr[co.C2S][co.TIME_LAST_ACK_TCP] = ts_delta
        if fin_flag:
            connections[conn_id].flow.attr[co.C2S][co.TIME_FIN_ACK_TCP] = ts_delta

        bytes_acked = (tcp.ack - acks[daddr, dport, saddr, sport][co.C2S]) % 4294967296
        if bytes_acked >= 2000000000:
            # Ack of 2GB or more is just not possible here
            return

        increment_value_dict(nb_acks[co.C2S][conn_id], bytes_acked)
        size_payload = ip.len - ip.hl * 4 - tcp.off * 4

        if size_payload > 0 and tcp.seq in acks[daddr, dport, saddr, sport][SEQ_S2C]:
            # This is a retransmission!
            connections[conn_id].flow.attr[co.S2C][co.TIME_LAST_PAYLD_WITH_RETRANS_TCP] = ts_delta
            connections[conn_id].flow.attr[co.S2C][co.TIMESTAMP_RETRANS].append((ts_delta,
                                                                                 ts_delta - acks[daddr, dport, saddr, sport][HSEQ_S2C][tcp.seq][0],
                                                                                 ts_delta - acks[daddr, dport, saddr, sport][HSEQ_S2C][tcp.seq][1],
                                                                                 ts_delta - acks[daddr, dport, saddr, sport][co.TIMESTAMP][SERVER]))
            acks[daddr, dport, saddr, sport][HSEQ_S2C][tcp.seq][1] = ts_delta
        elif size_payload > 0:
            acks[daddr, dport, saddr, sport][SEQ_S2C].add(tcp.seq)
            connections[conn_id].flow.attr[co.S2C][co.TIME_LAST_PAYLD_WITH_RETRANS_TCP] = ts_delta
            connections[conn_id].flow.attr[co.S2C][co.TIME_LAST_PAYLD_TCP] = ts_delta
            acks[daddr, dport, saddr, sport][HSEQ_S2C][tcp.seq] = [ts_delta, ts_delta]
            # Don't think will face this issue
#                                 if len(acks[daddr, dport, saddr, sport][SEQ][co.S2C]) >= 3000000:
#                                     for x in range(50000):
#                                         acks[daddr, dport, saddr, sport][SEQ][co.S2C].popleft()

    acks[daddr, dport, saddr, sport][co.C2S] = tcp.ack
    acks[daddr, dport, saddr, sport][co.TIMESTAMP][SERVER] = ts_delta


def compute_tcp_acks_retrans(pcap_filepath, connections, inverse_conns, ts_syn_timeout=6.0, ts_timeout=3600.0):
    """ Process a tcp pcap file and returns a dictionary of the number of cases an acknowledgement of x bytes is received
        It also compute the timestamps of retransmissions and put them in the connection
        It computes the timestamp of the last ACK, FIN and payload sent in both directions
    """
    print("Computing TCP ack sizes for", pcap_filepath)
    nb_acks = {co.C2S: {}, co.S2C: {}}
    acks = {}
    # Avoid processing packets that do not belong to any analyzed TCP connection
    black_list = set()
    pcap_file = open(pcap_filepath)
    pcap = dpkt.pcap.Reader(pcap_file)
    count = 0
    try:
        for ts, buf in pcap:
            ts_delta = get_ts_delta(ts)
            count += 1
            if count % 100000 == 0:
                print(count)
            # Check if linux cooked capture
            if pcap.datalink() == dpkt.pcap.DLT_LINUX_SLL:
                eth = dpkt.sll.SLL(buf)
            else:
                eth = dpkt.ethernet.Ethernet(buf)
            if type(eth.data) == dpkt.ip.IP or type(eth.data) == dpkt.ip6.IP6:
                ip = eth.data
                if type(ip.data) == dpkt.tcp.TCP:
                    tcp = ip.data
                    fin_flag = (tcp.flags & dpkt.tcp.TH_FIN) != 0
                    syn_flag = (tcp.flags & dpkt.tcp.TH_SYN) != 0
                    rst_flag = (tcp.flags & dpkt.tcp.TH_RST) != 0
                    ack_flag = (tcp.flags & dpkt.tcp.TH_ACK) != 0

                    saddr, daddr, sport, dport = get_ips_and_ports(eth, ip, tcp)
                    if syn_flag and not ack_flag and not fin_flag and not rst_flag:
                        process_first_syn(ts_delta, acks, nb_acks, connections, tcp, ip, saddr, daddr, sport, dport, black_list, inverse_conns,
                                          ts_syn_timeout, ts_timeout)

                    elif (saddr, sport, daddr, dport) in black_list:
                        continue

                    elif syn_flag and ack_flag and not fin_flag and not rst_flag:
                        process_syn_ack(ts_delta, acks, nb_acks, connections, tcp, saddr, ip, daddr, sport, dport, black_list, inverse_conns,
                                        ts_syn_timeout, ts_timeout)

                    elif not syn_flag and not rst_flag and ack_flag:
                        if (saddr, sport, daddr, dport) in acks:
                            process_pkt_from_client(ts_delta, acks, nb_acks, connections, tcp, ip, saddr, daddr, sport, dport, fin_flag)

                        elif (daddr, dport, saddr, sport) in acks:
                            process_pkt_from_server(ts_delta, acks, nb_acks, connections, tcp, ip, saddr, daddr, sport, dport, fin_flag)
                        else:
                            # Silently ignore those packets
                            # print(saddr, sport, daddr, dport, "haven't seen beginning...")
                            continue

    except dpkt.NeedData as e:
        print(e, ": trying to continue...", file=sys.stderr)

    return nb_acks


def get_dss_and_data_ack(tcp):
    """ Return the DSS and Data ACK of the current packet or False if there is no DSS """
    dss, dack, dss_is_8_bytes = False, False, False
    opt_list = dpkt.tcp.parse_opts(tcp.opts)
    for option_num, option_content in opt_list:
        # Only interested in MPTCP with subtype 2
        if option_num == 30 and len(option_content):
            if ord(option_content[0]) == 32:
                flags = ord(option_content[1])
                dss_is_8_bytes = (flags & 0x08) != 0
                dss_is_present = (flags & 0x04) != 0
                dack_is_8_bytes = (flags & 0x02) != 0
                dack_is_present = (flags & 0x01) != 0
                if dack_is_present and not dss_is_present:
                    range_max = 8 if dack_is_8_bytes else 4
                    dack = 0
                    for i in range(range_max):
                        dack = dack * 256 + ord(option_content[2 + i])

                elif dss_is_present and dack_is_present:
                    range_max_dack = 8 if dack_is_8_bytes else 4
                    dack = 0
                    for i in range(range_max_dack):
                        dack = dack * 256 + ord(option_content[2 + i])

                    start_dss = 2 + range_max_dack
                    range_max_dss = 8 if dss_is_8_bytes else 4
                    dss = 0
                    for i in range(range_max_dss):
                        dss = dss * 256 + ord(option_content[start_dss + i])

                elif dss_is_present and not dack_is_present:
                    global dss_not_ack_warning
                    if not dss_not_ack_warning:
                        print("Case where dss_is_present and dack is not present (not compliant with Linux implementation): continue", file=sys.stderr)
                        dss_not_ack_warning = True

                    start_dss = 2
                    range_max_dss = 8 if dss_is_8_bytes else 4
                    dss = 0
                    for i in range(range_max_dss):
                        dss = dss * 256 + ord(option_content[start_dss + i])

    return dss, dack, dss_is_8_bytes


def process_mptcp_first_syn(ts_delta, acks, conn_acks, mptcp_connections, tcp, ip, saddr, daddr, sport, dport, black_list, fast_conns, ts_syn_timeout, ts_timeout):
    """ Processing of the first SYNs seen on a connection for the MPTCP DSS retransmissions """
    # The sender of the first SYN is the client
    # Check if the connection is black listed or not
    conn_id = False
    conn_candidates = fast_conns.get((saddr, daddr, sport, dport), [])
    min_delta = ts_syn_timeout
    for start, duration, cid, fid in conn_candidates:
        if (co.START in mptcp_connections[cid].flows[fid].attr
                and abs((ts_delta - mptcp_connections[cid].flows[fid].attr[co.START]).total_seconds()) < min_delta):
            conn_id = cid
            flow_id = fid
            min_delta = abs((ts_delta - mptcp_connections[cid].flows[fid].attr[co.START]).total_seconds())

    if not conn_id:
        black_list.add((saddr, sport, daddr, dport))
        return
    elif conn_id and (saddr, sport, daddr, dport) in black_list:
        black_list.remove((saddr, sport, daddr, dport))

    if ((saddr, sport, daddr, dport) in acks and (ts_delta - acks[saddr, sport, daddr, dport][co.TIMESTAMP][CLIENT]).total_seconds() <= ts_syn_timeout
            and acks[saddr, sport, daddr, dport][co.S2C] == -1) and conn_id in conn_acks:
        # SYN retransmission! But do nothing particular
        acks[saddr, sport, daddr, dport][co.TIMESTAMP][CLIENT] = ts_delta
        conn_acks[conn_id][co.TIMESTAMP][CLIENT] = ts_delta
    else:
        acks[saddr, sport, daddr, dport] = {co.C2S: -1, co.S2C: -1, co.TIMESTAMP: {CLIENT: ts_delta, SERVER: None}, co.CONN_ID: conn_id,
                                            co.FLOW_ID: flow_id}
        conn_acks[conn_id] = {co.C2S: -1, co.S2C: -1, co.TIMESTAMP: {CLIENT: ts_delta, SERVER: None}, SEQ_C2S: set(), SEQ_S2C: set(), HSEQ_C2S: {},
                              HSEQ_S2C: {}}


def process_mptcp_syn_ack(ts_delta, acks, conn_acks, mptcp_connections, tcp, ip, saddr, daddr, sport, dport, black_list, fast_conns, ts_syn_timeout, ts_timeout):
    """ Processing of SYN/ACKs seen on the connection for the MPTCP DSS retransmissions """
    # The sender of the SYN/ACK is the server
    if (daddr, dport, saddr, sport) in acks and ((ts_delta - acks[daddr, dport, saddr, sport][co.TIMESTAMP][CLIENT]).total_seconds() < ts_timeout
                                                 and acks[daddr, dport, saddr, sport][co.C2S] == -1):
        # Better to check, if not seen, maybe uncomplete TCP connection
        acks[daddr, dport, saddr, sport][co.C2S] = tcp.ack
        acks[daddr, dport, saddr, sport][co.TIMESTAMP][SERVER] = ts_delta
        conn_acks[acks[daddr, dport, saddr, sport][co.CONN_ID]][co.TIMESTAMP][SERVER] = ts_delta

    elif (daddr, dport, saddr, sport) in acks and ((ts_delta - acks[daddr, dport, saddr, sport][co.TIMESTAMP][CLIENT]).total_seconds() < ts_timeout
                                                   and tcp.ack == acks[daddr, dport, saddr, sport][co.C2S]):
        # SYN/ACK retransmission! But don't do anything special
        acks[daddr, dport, saddr, sport][co.TIMESTAMP][SERVER] = ts_delta
        conn_acks[acks[daddr, dport, saddr, sport][co.CONN_ID]][co.TIMESTAMP][SERVER] = ts_delta


def process_mptcp_pkt_from_client(ts_delta, acks, conn_acks, mptcp_connections, tcp, ip, saddr, daddr, sport, dport):
    """ Process a packet with ACK set from the client for the MPTCP DSS retransmissions """
    dss, dack, dss_is_8_bytes = get_dss_and_data_ack(tcp)
    conn_id = acks[saddr, sport, daddr, dport][co.CONN_ID]
    flow_id = acks[saddr, sport, daddr, dport][co.FLOW_ID]
    if conn_acks[conn_id][co.S2C] >= 0:
        max_val = 2**64 if dss_is_8_bytes else 2**32
        bytes_acked = (dack - conn_acks[conn_id][co.S2C]) % max_val
        if bytes_acked >= 2000000000:
            # Ack of 2GB or more is just not possible here
            return

        size_payload = ip.len - ip.hl * 4 - tcp.off * 4

        if (size_payload > 0 and dss in conn_acks[conn_id][SEQ_C2S] and (dss - conn_acks[conn_id][co.C2S]) % max_val < 2000000000
                and (mptcp_connections[conn_id].attr[co.C2S][co.TIME_LAST_ACK_TCP] - ts_delta).total_seconds() > 0.0):
            # This is a DSS retransmission! (take into account the seq overflow)
            mptcp_connections[conn_id].attr[co.C2S][co.RETRANS_DSS].append((ts_delta, flow_id, dss, conn_acks[conn_id][HSEQ_C2S][dss][2],
                                                                            ts_delta - conn_acks[conn_id][HSEQ_C2S][dss][0],
                                                                            ts_delta - conn_acks[conn_id][HSEQ_C2S][dss][1],
                                                                            ts_delta - conn_acks[conn_id][co.TIMESTAMP][CLIENT]))
            conn_acks[conn_id][HSEQ_C2S][dss][1] = ts_delta
        elif size_payload > 0 and dss is not False:
            conn_acks[conn_id][SEQ_C2S].add(dss)
            conn_acks[conn_id][HSEQ_C2S][dss] = [ts_delta, ts_delta, ts_delta - conn_acks[conn_id][co.TIMESTAMP][CLIENT]]

    conn_acks[conn_id][co.S2C] = dack
    acks[saddr, sport, daddr, dport][co.TIMESTAMP][CLIENT] = ts_delta
    conn_acks[conn_id][co.TIMESTAMP][CLIENT] = ts_delta


def process_mptcp_pkt_from_server(ts_delta, acks, conn_acks, mptcp_connections, tcp, ip, saddr, daddr, sport, dport):
    """ Process a packet with ACK set from the server for the MPTCP DSS retransmissions """
    dss, dack, dss_is_8_bytes = get_dss_and_data_ack(tcp)
    conn_id = acks[daddr, dport, saddr, sport][co.CONN_ID]
    flow_id = acks[daddr, dport, saddr, sport][co.FLOW_ID]
    if conn_acks[conn_id][co.C2S] >= 0:
        max_val = 2**64 if dss_is_8_bytes else 2**32
        bytes_acked = (dack - conn_acks[conn_id][co.C2S]) % max_val
        if bytes_acked >= 2000000000:
            # Ack of 2GB or more is just not possible here
            return

        size_payload = ip.len - ip.hl * 4 - tcp.off * 4

        if (size_payload > 0 and dss in conn_acks[conn_id][SEQ_S2C] and (dss - conn_acks[conn_id][co.S2C]) % max_val < 2000000000
                and (mptcp_connections[conn_id].attr[co.S2C][co.TIME_LAST_ACK_TCP] - ts_delta).total_seconds() > 0.0):
            # This is a DSS retransmission!
            mptcp_connections[conn_id].attr[co.S2C][co.RETRANS_DSS].append((ts_delta, flow_id, dss, conn_acks[conn_id][HSEQ_S2C][dss][2],
                                                                            ts_delta - conn_acks[conn_id][HSEQ_S2C][dss][0],
                                                                            ts_delta - conn_acks[conn_id][HSEQ_S2C][dss][1],
                                                                            ts_delta - conn_acks[conn_id][co.TIMESTAMP][SERVER]))
            conn_acks[conn_id][HSEQ_S2C][dss][1] = ts_delta
        elif size_payload > 0 and dss is not False:
            conn_acks[conn_id][SEQ_S2C].add(dss)
            conn_acks[conn_id][HSEQ_S2C][dss] = [ts_delta, ts_delta, ts_delta - conn_acks[conn_id][co.TIMESTAMP][SERVER]]

    conn_acks[conn_id][co.C2S] = dack
    acks[daddr, dport, saddr, sport][co.TIMESTAMP][SERVER] = ts_delta
    conn_acks[conn_id][co.TIMESTAMP][SERVER] = ts_delta


def compute_mptcp_dss_retransmissions(pcap_filepath, mptcp_connections, fast_conns, ts_syn_timeout=6.0, ts_timeout=3600.0):
    """ Compute MPTCP DSS retransmissions (avoid taking into account spurious ones) """
    print("Computing MPTCP DSS retransmissions for", pcap_filepath)
    acks = {}
    conn_acks = {}
    # Avoid processing packets that do not belong to any analyzed TCP connection
    black_list = set()
    pcap_file = open(pcap_filepath)
    pcap = dpkt.pcap.Reader(pcap_file)
    count = 0
    for ts, buf in pcap:
        ts_delta = get_ts_delta(ts)
        count += 1
        if count % 100000 == 0:
            print(count)
        eth = dpkt.ethernet.Ethernet(buf)
        if type(eth.data) == dpkt.ip.IP or type(eth.data) == dpkt.ip6.IP6:
            ip = eth.data
            if type(ip.data) == dpkt.tcp.TCP:
                tcp = ip.data
                fin_flag = (tcp.flags & dpkt.tcp.TH_FIN) != 0
                syn_flag = (tcp.flags & dpkt.tcp.TH_SYN) != 0
                rst_flag = (tcp.flags & dpkt.tcp.TH_RST) != 0
                ack_flag = (tcp.flags & dpkt.tcp.TH_ACK) != 0

                saddr, daddr, sport, dport = get_ips_and_ports(eth, ip, tcp)

                if syn_flag and not ack_flag and not fin_flag and not rst_flag:
                    process_mptcp_first_syn(ts_delta, acks, conn_acks, mptcp_connections, tcp, ip, saddr, daddr, sport, dport, black_list, fast_conns,
                                            ts_syn_timeout, ts_timeout)

                elif (saddr, sport, daddr, dport) in black_list:
                    continue

                elif syn_flag and ack_flag and not fin_flag and not rst_flag:
                    process_mptcp_syn_ack(ts_delta, acks, conn_acks, mptcp_connections, tcp, ip, saddr, daddr, sport, dport, black_list, fast_conns,
                                          ts_syn_timeout, ts_timeout)

                elif not syn_flag and not rst_flag and ack_flag:
                    if (saddr, sport, daddr, dport) in acks:
                        process_mptcp_pkt_from_client(ts_delta, acks, conn_acks, mptcp_connections, tcp, ip, saddr, daddr, sport, dport)

                    elif (daddr, dport, saddr, sport) in acks:
                        process_mptcp_pkt_from_server(ts_delta, acks, conn_acks, mptcp_connections, tcp, ip, saddr, daddr, sport, dport)
                    else:
                        # Silently ignore those packets
                        # print(saddr, sport, daddr, dport, "haven't seen beginning...")
                        continue


def process_trace(pcap_filepath, graph_dir_exp, stat_dir_exp, failed_conns_dir_exp, acksize_tcp_dir_exp, tcpcsm, mptcp_connections=None, print_out=sys.stdout, light=False, return_dict=False):
    """ Process a tcp pcap file and generate stats of its connections """
    cmd = ['tstat', '-s', os.path.basename(pcap_filepath[:-5]), pcap_filepath]

    keep_tstat_log = False if return_dict else True

    try:
        connections = process_tstat_cmd(cmd, pcap_filepath, keep_log=keep_tstat_log, graph_dir_exp=graph_dir_exp)
    except TstatError as e:
        print(str(e) + ": skip process", file=sys.stderr)
        return

    # Directory containing all TCPConnections that tried to be MPTCP subflows, but failed to
    failed_conns = {}

    if tcpcsm:
        retransmissions_tcpcsm(pcap_filepath, connections)

    acksize_all = {co.C2S: {}, co.S2C: {}}

    if not light:
        inverse_conns = create_inverse_tcp_dictionary(connections)

        acksize_all = compute_tcp_acks_retrans(pcap_filepath, connections, inverse_conns)

    acksize_all_mptcp = {co.C2S: {}, co.S2C: {}}

    if mptcp_connections:
        fast_conns = get_preprocessed_connections(mptcp_connections)
        for flow_id in connections:
            # Copy info to mptcp connections
            copy_info_to_mptcp_connections(connections, mptcp_connections, failed_conns, acksize_all, acksize_all_mptcp, flow_id,
                                           fast_conns=fast_conns)

        if not light:
            for conn_id, conn in mptcp_connections.iteritems():
                for direction in co.DIRECTIONS:
                    max_ack = timedelta(0)
                    max_payload = timedelta(0)
                    for flow_id, flow in conn.flows.iteritems():
                        if co.TIME_LAST_ACK_TCP in flow.attr[direction] and (flow.attr[direction][co.TIME_LAST_ACK_TCP] - max_ack).total_seconds() > 0.0:
                            max_ack = flow.attr[direction][co.TIME_LAST_ACK_TCP]

                        if co.TIME_LAST_PAYLD_TCP in flow.attr[direction] and (flow.attr[direction][co.TIME_LAST_PAYLD_TCP] - max_payload).total_seconds() > 0.0:
                            max_payload = flow.attr[direction][co.TIME_LAST_PAYLD_TCP]

                    mptcp_connections[conn_id].attr[direction][co.TIME_LAST_ACK_TCP] = max_ack
                    mptcp_connections[conn_id].attr[direction][co.TIME_LAST_PAYLD_TCP] = max_payload

            try:
                compute_mptcp_dss_retransmissions(pcap_filepath, mptcp_connections, fast_conns)
            except dpkt.NeedData as e:
                print(e, ": trying to continue...", file=sys.stderr)

    if return_dict:
        if mptcp_connections:
            return connections, acksize_all_mptcp
        else:
            return connections, acksize_all
    else:
        # Save connections info
        if mptcp_connections:
            co.save_data(pcap_filepath, acksize_tcp_dir_exp, acksize_all_mptcp)
            # Also save TCP connections that failed to be MPTCP subflows
            co.save_data(pcap_filepath, failed_conns_dir_exp, failed_conns)
        else:
            co.save_data(pcap_filepath, acksize_tcp_dir_exp, acksize_all)
            co.save_data(pcap_filepath, stat_dir_exp, connections)
