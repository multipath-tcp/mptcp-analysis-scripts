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
import os
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


def compute_duration(info):
    """ Given the output of tcptrace as an array, compute the duration of a tcp connection
        The computation done (in term of tcptrace's attributes) is last_packet - first_packet
    """
    first_packet = float(info[5])
    last_packet = float(info[6])
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
                connection.flow.attr[co.SADDR] = info[1]
                connection.flow.attr[co.DADDR] = info[2]
                connection.flow.attr[co.SPORT] = info[3]
                connection.flow.attr[co.DPORT] = info[4]
                connection.flow.detect_ipv4()
                connection.flow.indicates_wifi_or_rmnet()
                connection.flow.attr[co.START] = float(info[5])
                connection.flow.attr[co.DURATION] = compute_duration(info)
                connection.flow.attr[co.PACKS_S2D] = int(info[7])
                connection.flow.attr[co.PACKS_D2S] = int(info[8])
                # Note that this count is about unique_data_bytes
                connection.flow.attr[co.BYTES_S2D] = int(info[21])
                connection.flow.attr[co.BYTES_D2S] = int(info[22])

                connection.flow.attr[co.PACKS_RETRANS_S2D] = int(info[27])
                connection.flow.attr[co.PACKS_RETRANS_D2S] = int(info[28])
                connection.flow.attr[co.BYTES_RETRANS_S2D] = int(info[29])
                connection.flow.attr[co.BYTES_RETRANS_D2S] = int(info[30])

                connection.flow.attr[co.PACKS_OOO_S2D] = int(info[35])
                connection.flow.attr[co.PACKS_OOO_D2S] = int(info[36])
                # TODO maybe extract more information

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
            co.move_file(pcap_flow_data_path, os.path.join(
                graph_dir_exp, co.CSV_DIR, os.path.basename(pcap_filepath[:-5]) + "_" + os.path.basename(pcap_flow_data_path)))
        except IOError as e:
            print(str(e), file=sys.stderr)
    else:
        os.remove(pcap_flow_data_path)
    return connections

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

    co.move_file(tmp_remain_filepath, remain_pcap_filepath, print_out=print_out)

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
            co.move_file(tmp_filter_filepath, pcap_filepath, print_out=print_out)
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
    if (not connections[flow_name].flow.attr[co.TYPE] == 'IPv4' or connections[flow_name].flow.attr[co.IF]):
        if is_reversed:
            return (connections[flow_name].flow.attr[co.PACKS_D2S] > 0)
        else:
            return (connections[flow_name].flow.attr[co.PACKS_S2D] > 0)
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
        for flow_id, flow in conn.flows.iteritems():
            if (connection.flow.attr[co.SADDR] == flow.attr[co.SADDR] and
                    connection.flow.attr[co.DADDR] == flow.attr[co.DADDR] and
                    connection.flow.attr[co.SPORT] == flow.attr[co.SPORT] and
                    connection.flow.attr[co.DPORT] == flow.attr[co.DPORT]):
                return conn_id, flow_id

    return None, None


def prepare_connections_objects(connections, mptcp_connections):
    """ Prepare connections objects """
    if mptcp_connections:
        for conn_id, conn in mptcp_connections.iteritems():
            conn.attr[co.S2D] = {}
            conn.attr[co.D2S] = {}
    else:
        for conn_id, conn in connections.iteritems():
            conn.attr[co.S2D] = {}
            conn.attr[co.D2S] = {}


def copy_info_to_mptcp_connections(connection, mptcp_connections):
    """ Given a tcp connection, copy its start and duration to the corresponding mptcp connection
        Return the corresponding connection and flow ids of the mptcp connection
    """
    conn_id, flow_id = get_flow_name_connection(connection, mptcp_connections)
    if conn_id:
        mptcp_connections[conn_id].flows[flow_id].attr[co.START] = connection.flow.attr[co.START]
        mptcp_connections[conn_id].flows[flow_id].attr[co.DURATION] = connection.flow.attr[co.DURATION]
        mptcp_connections[conn_id].flows[flow_id].attr[co.PACKS_S2D] = connection.flow.attr[co.PACKS_S2D]
        mptcp_connections[conn_id].flows[flow_id].attr[co.PACKS_D2S] = connection.flow.attr[co.PACKS_D2S]
        mptcp_connections[conn_id].flows[flow_id].attr[
            co.PACKS_RETRANS_S2D] = connection.flow.attr[co.PACKS_RETRANS_S2D]
        mptcp_connections[conn_id].flows[flow_id].attr[
            co.PACKS_RETRANS_D2S] = connection.flow.attr[co.PACKS_RETRANS_D2S]
        mptcp_connections[conn_id].flows[flow_id].attr[
            co.BYTES_RETRANS_S2D] = connection.flow.attr[co.BYTES_RETRANS_S2D]
        mptcp_connections[conn_id].flows[flow_id].attr[
            co.BYTES_RETRANS_D2S] = connection.flow.attr[co.BYTES_RETRANS_D2S]
        mptcp_connections[conn_id].flows[flow_id].attr[co.PACKS_OOO_S2D] = connection.flow.attr[co.PACKS_OOO_S2D]
        mptcp_connections[conn_id].flows[flow_id].attr[co.PACKS_OOO_D2S] = connection.flow.attr[co.PACKS_OOO_D2S]
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


def process_tsg_xpl_file(pcap_filepath, xpl_filepath, graph_dir_exp, connections, aggregate_dict, cwin_data_all, flow_name, relative_start, is_reversed, mptcp_connections, conn_id, flow_id):
    """ Prepare gpl file for the (possible) plot and aggregate its content
        Also update connections or mptcp_connections with the processed data
    """
    prepare_xpl_file(xpl_filepath, connections, flow_name, relative_start)
    aggregate_tsg, adv_rwin = get_upper_packets_in_flight_and_adv_rwin(xpl_filepath, flow_name)
    create_congestion_window_data(
        aggregate_tsg, adv_rwin, pcap_filepath, cwin_data_all, is_reversed, connections, flow_name, mptcp_connections, conn_id, flow_id)
    interface = connections[flow_name].flow.attr[co.IF]
    if is_reversed:
        aggregate_dict[co.D2S][interface] += aggregate_tsg
        if mptcp_connections:
            if conn_id:
                mptcp_connections[conn_id].flows[flow_id].attr[
                    co.BYTES_D2S] = connections[flow_name].flow.attr[co.BYTES_D2S]
                if interface in mptcp_connections[conn_id].attr[co.D2S].keys():
                    mptcp_connections[conn_id].attr[co.D2S][
                        interface] += connections[flow_name].flow.attr[co.BYTES_D2S]
                else:
                    mptcp_connections[conn_id].attr[co.D2S][
                        interface] = connections[flow_name].flow.attr[co.BYTES_D2S]
        else:
            connections[flow_name].attr[co.D2S][interface] = connections[
                flow_name].flow.attr[co.BYTES_D2S]
    else:
        aggregate_dict[co.S2D][interface] += aggregate_tsg
        if mptcp_connections:
            if conn_id:
                mptcp_connections[conn_id].flows[flow_id].attr[
                    co.BYTES_S2D] = connections[flow_name].flow.attr[co.BYTES_S2D]
                if interface in mptcp_connections[conn_id].attr[co.S2D].keys():
                    mptcp_connections[conn_id].attr[co.S2D][
                        interface] += connections[flow_name].flow.attr[co.BYTES_S2D]
                else:
                    mptcp_connections[conn_id].attr[co.S2D][
                        interface] = connections[flow_name].flow.attr[co.BYTES_S2D]
        else:
            connections[flow_name].attr[co.S2D][interface] = connections[
                flow_name].flow.attr[co.BYTES_S2D]


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


def process_trace(pcap_filepath, graph_dir_exp, stat_dir_exp, aggl_dir_exp, plot_cwin, mptcp_connections=None, print_out=sys.stdout, min_bytes=0):
    """ Process a tcp pcap file and generate graphs of its connections """
    # -C for color, -S for sequence numbers, -T for throughput graph
    # -zxy to plot both axes to 0
    # -n to avoid name resolution
    # -y to remove some noise in sequence graphs
    # -l for long output
    # --csv for csv file
    cmd = ['tcptrace', '--output_dir=' + os.getcwd(),
           '--output_prefix=' +
           os.path.basename(pcap_filepath[:-5]) + '_', '-C', '-S', '-T', '-zxy',
           '-n', '-y', '-l', '--csv', pcap_filepath]

    try:
        connections = process_tcptrace_cmd(cmd, pcap_filepath, keep_csv=True, graph_dir_exp=graph_dir_exp)
    except TCPTraceError as e:
        print(str(e) + ": skip process", file=sys.stderr)
        return

    relative_start = get_relative_start_time(connections)
    aggregate_dict = {
        co.S2D: {co.WIFI: [], co.RMNET: []}, co.D2S: {co.WIFI: [], co.RMNET: []}}

    prepare_connections_objects(connections, mptcp_connections)
    # The dictionary where all cwin data of the scenario will be stored
    cwin_data_all = {}

    # The tcptrace call will generate .xpl files to cope with
    for xpl_filepath in glob.glob(os.path.join(os.getcwd(), os.path.basename(pcap_filepath[:-5]) + '*.xpl')):
        conn_id, flow_id = None, None
        flow_name, is_reversed = get_flow_name(xpl_filepath)
        if mptcp_connections:
            conn_id, flow_id = copy_info_to_mptcp_connections(connections[flow_name], mptcp_connections)

        if interesting_graph(flow_name, is_reversed, connections) and 'tsg' in os.path.basename(xpl_filepath):
            process_tsg_xpl_file(pcap_filepath, xpl_filepath, graph_dir_exp, connections, aggregate_dict, cwin_data_all,
                                 flow_name, relative_start, is_reversed, mptcp_connections, conn_id, flow_id)

        try:
            if mptcp_connections:
                # If mptcp, don't keep tcptrace plots
                os.remove(xpl_filepath)
            else:
                co.move_file(xpl_filepath, os.path.join(graph_dir_exp, co.TSG_THGPT_DIR), print_out=print_out)
        except OSError as e:
            print(str(e) + ": skipped", file=sys.stderr)
        except IOError as e:
            print(str(e) + ": skipped", file=sys.stderr)

    plot_aggregated_results(pcap_filepath, graph_dir_exp, aggregate_dict)

    # Save aggregated graphs (even it's not connections)
    co.save_data(pcap_filepath, aggl_dir_exp, aggregate_dict)

    # Save connections info
    if mptcp_connections:
        # Returns to the caller the data to plot cwin
        return cwin_data_all
    else:
        if plot_cwin:
            plot_congestion_graphs(pcap_filepath, graph_dir_exp, cwin_data_all)
        co.save_data(pcap_filepath, stat_dir_exp, connections)
