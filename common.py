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

from __future__ import print_function

##################################################
##                   IMPORTS                    ##
##################################################

import os
import matplotlib
# Do not use any X11 backend
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pickle
import statsmodels.api as sm
import subprocess
import sys
import tempfile
import threading
import traceback


# # This import must be done here, because of the internals of matplotlib
# from matplotlib.backends.backend_pgf import FigureCanvasPgf
# matplotlib.backend_bases.register_backend('pdf', FigureCanvasPgf)
#
# pgf_with_pdflatex = {
#     "pgf.texsystem": "pdflatex",
#     ##"pgf.preamble": [
#     ##    r'\usepackage{amsmath}',
#     ##    r'\usepackage[scientific-notation=true]{siunitx}',
#     ##      r"\usepackage[utf8x]{inputenc}",
#     ##      r"\usepackage[T1]{fontenc}",
#     ##    ]
# }
# matplotlib.rcParams.update(pgf_with_pdflatex)

##################################################
##               COMMON CLASSES                 ##
##################################################

class cd:

    """Context manager for changing the current working directory"""

    def __init__(self, newPath):
        self.newPath = newPath

    def __enter__(self):
        self.savedPath = os.getcwd()
        os.chdir(self.newPath)

    def __exit__(self, etype, value, traceback):
        os.chdir(self.savedPath)


##################################################
##              COMMON EXCEPTIONS               ##
##################################################


class TSharkError(Exception):
    pass


##################################################
##               COMMON CONSTANTS               ##
##################################################
# Lines in xpl files that starts with one of the words in XPL_ONE_POINT have one point
XPL_ONE_POINT = ['darrow', 'uarrow', 'diamond', 'dot', 'atext', 'dtick', 'utick', 'atext']
# Lines in xpl files that starts with one of the words in XPL_TWO_POINTS have two points
XPL_TWO_POINTS = ['line']

# The default stat directory
DEF_STAT_DIR = 'stats'
# The default aggl directory
DEF_AGGL_DIR = 'aggls'
# The default sums directory
DEF_SUMS_DIR = 'sums'
# The default interface to analyse
DEF_IFACE = 'any'

# The time sequence and throughput graphs directory
TSG_THGPT_DIR = 'tsg_thgpt'
# The congestion window graphs directory
CWIN_DIR = 'cwin'
# The agglomerated graphs directory
AGGL_DIR = 'aggl'
# The directory of csv files
CSV_DIR = 'csv'

# Following constants are used to make the code cleaner and more robust (for dictionary)
# Those are mainly determined by the output of mptcptrace
RMNET = 'rmnet'
WIFI = 'wifi'
# IPv4 or IPv6
TYPE = 'type'
# Interface: RMNET or WIFI
IF = 'interface'
# Source IP address
SADDR = 'saddr'
# Destination IP address
DADDR = 'daddr'
# Source port
SPORT = 'sport'
# Destination port
DPORT = 'dport'
# Window scale for source
WSCALESRC = 'wscalesrc'
# Window scale for destination
WSCALEDST = 'wscaledst'
# Start of a connection (first packet)
START = 'start_time'
# Duration of a connection
DURATION = 'duration'
# Number of packets from source to destination
PACKS_S2D = 'packets_source2destination'
# Number of packets from destination to source
PACKS_D2S = 'packets_destination2source'
# Number of bytes from source to destination
BYTES_S2D = 'bytes_source2destination'
# Number of bytes from destination to source
BYTES_D2S = 'bytes_destination2source'
# Number of packets retransmitted from source to destination
PACKS_RETRANS_S2D = 'packets_retrans_source2destination'
# Number of packets retransmitted from destination to source
PACKS_RETRANS_D2S = 'packets_retrans_destination2source'
# Number of bytes retransmitted from source to destination
BYTES_RETRANS_S2D = 'bytes_retrans_source2destination'
# Number of bytes retransmitted from destination to source
BYTES_RETRANS_D2S = 'bytes_retrans_destination2source'
# Number of packets out of orders from source to destination
PACKS_OOO_S2D = 'packets_outoforder_source2destination'
# Number of packets out of orders from destination to source
PACKS_OOO_D2S = 'packets_outoforder_destination2source'
# Congestion window graph data dictionary
CWIN_DATA = 'congestion_window_data'
# Reinjected packets from source to destination
REINJ_ORIG_PACKS_S2D = 'reinjected_orig_packets_source2destination'
# Reinjected packets from destination to source
REINJ_ORIG_PACKS_D2S = 'reinjected_orig_packets_destination2source'
# Reinjected bytes from source to destination
REINJ_ORIG_BYTES_S2D = 'reinjected_orig_bytes_source2destination'
# Reinjected bytes from destination to source
REINJ_ORIG_BYTES_D2S = 'reinjected_orig_bytes_destination2source'

# RTT info
RTT_SAMPLES_S2D = 'rtt_samples_s2d'
RTT_SAMPLES_D2S = 'rtt_samples_d2s'
RTT_MIN_S2D = 'rtt_min_s2d'
RTT_MIN_D2S = 'rtt_min_d2s'
RTT_MAX_S2D = 'rtt_max_s2d'
RTT_MAX_D2S = 'rtt_max_d2s'
RTT_AVG_S2D = 'rtt_avg_s2d'
RTT_AVG_D2S = 'rtt_avg_d2s'
RTT_STDEV_S2D = 'rtt_stdev_s2d'
RTT_STDEV_D2S = 'rtt_stdev_d2s'

# For aggregation
S2D = 'source2destination'
D2S = 'destination2source'

# IPv4 localhost address
LOCALHOST_IPv4 = '127.0.0.1'
# Port number of RedSocks
PORT_RSOCKS = '8123'
# Prefix of the Wi-Fi interface IP address
PREFIX_WIFI_IF = '192.168.'
# Size of Latin alphabet
SIZE_LAT_ALPH = 26
# IP address of the proxy
IP_PROXY = False

PREFIX_IP_WIFI = False

if os.path.isfile('config.py'):
    import config as conf
    IP_PROXY = conf.IP_PROXY
    PREFIX_IP_WIFI = conf.PREFIX_IP_WIFI


##################################################
##             CONNECTION RELATED               ##
##################################################


class BasicFlow(object):

    """ Represent a flow between two hosts at transport layer """
    attr = {}

    def __init__(self):
        self.attr = {}

    def indicates_wifi_or_rmnet(self):
        """ Given data of a mptcp connection subflow, indicates if comes from wifi or rmnet """
        if self.attr[SADDR].startswith(PREFIX_WIFI_IF) or self.attr[DADDR].startswith(PREFIX_WIFI_IF) or self.attr[SADDR].startswith(PREFIX_IP_WIFI) or self.attr[DADDR].startswith(PREFIX_IP_WIFI):
            self.attr[IF] = WIFI
        else:
            self.attr[IF] = RMNET

    def detect_ipv4(self):
        """ Given the dictionary of a TCP connection, add the type IPv4 if it is an IPv4 connection """
        saddr = self.attr[SADDR]
        daddr = self.attr[DADDR]
        num_saddr = saddr.split('.')
        num_daddr = daddr.split('.')
        if len(num_saddr) == 4 and len(num_daddr) == 4:
            self.attr[TYPE] = 'IPv4'


class BasicConnection(object):

    """ Represent a connection between two hosts at high level """
    conn_id = ""
    attr = {}

    def __init__(self, cid):
        self.conn_id = cid
        self.attr = {}


##################################################
##         (DE)SERIALIZATION OF OBJECTS         ##
##################################################


def save_object(obj, fname):
    """ Save the object obj in the file with filename fname """
    file = open(fname, 'wb')
    file.write(pickle.dumps(obj))
    file.close()


def load_object(fname):
    """ Return the object contained in the file with filename fname """
    file = open(fname, 'rb')
    obj = pickle.loads(file.read())
    file.close()
    return obj

##################################################
##               COMMON FUNCTIONS               ##
##################################################


def check_directory_exists(directory):
    """ Check if the directory exists, and create it if needed
        If directory is a file, exit the program
    """
    if os.path.exists(directory):
        if not os.path.isdir(directory):
            print(directory + " is a file: stop", file=sys.stderr)
            sys.exit(1)
    else:
        os.makedirs(directory)


def get_dir_from_arg(directory, end=''):
    """ Get the abspath of the dir given by the user and append 'end' """
    if end.endswith('.'):
        end = end[:-1]
    if directory.endswith('/'):
        directory = directory[:-1]
    return os.path.abspath(os.path.expanduser(directory)) + end


def is_number(s):
    """ Check if the str s is a number """
    try:
        float(s)
        return True
    except ValueError:
        return False


def count_mptcp_subflows(data):
    """ Count the number of subflows of a MPTCP connection """
    count = 0
    for key, value in data.iteritems():
        # There could have "pure" data in the connection
        if isinstance(value, dict):
            count += 1

    return count


def move_file(from_path, to_path, print_out=sys.stderr):
    """ Move a file, raise an IOError if it fails """
    cmd = ['mv', from_path, to_path]
    if subprocess.call(cmd, stdout=print_out) != 0:
        raise IOError("Error when moving " + from_path + " to " + to_path)


def tshark_filter(condition, src_path, dst_path, print_out=sys.stderr):
    """ Filter src_path using the condition and write the result to dst_path
        Raise a TSharkError in case of failure
    """
    cmd = ['tshark', '-r', src_path, '-Y', condition, '-w', dst_path]
    if subprocess.call(cmd, stdout=print_out) != 0:
        raise co.TSharkError("Error with condition " + condition + " for source " + src_path + " and destination "
                             + dst_path)


##################################################
##                   PCAP                       ##
##################################################


def copy_remain_pcap_file(pcap_filepath, print_out=sys.stdout):
    """ Given a pcap file path, return the file path of a copy, used for correction of traces """
    remain_pcap_filepath = pcap_filepath[:-5] + "__rem.pcap"
    cmd = ['cp', pcap_filepath, remain_pcap_filepath]
    if subprocess.call(cmd, stdout=print_out) != 0:
        print("Error when copying " + pcap_filepath + ": skip tcp correction", file=sys.stderr)
        return None
    return remain_pcap_filepath


def save_data(filepath, dir_exp, data):
    """ Using the name pcap_fname, save data in a file with filename fname in dir dir_exp """
    path_name = os.path.join(
        dir_exp, os.path.basename(filepath)[:-5])
    try:
        data_file = open(path_name, 'w')
        pickle.dump(data, data_file)
        data_file.close()
    except IOError as e:
        print(str(e) + ': no data file for ' + filepath, file=sys.stderr)


def clean_loopback_pcap(pcap_filepath, print_out=sys.stdout):
    """ Remove noisy traffic (port 1984), see netstat """
    tmp_pcap = tempfile.mkstemp(suffix='.pcap')[1]
    cmd = ['tshark', '-Y', '!(tcp.dstport==1984||tcp.srcport==1984)&&!((ip.src==127.0.0.1)&&(ip.dst==127.0.0.1))', '-r',
           pcap_filepath, '-w', tmp_pcap, '-F', 'pcap']
    if subprocess.call(cmd, stdout=print_out) != 0:
        print("Error in cleaning " + pcap_filepath, file=sys.stderr)
        return
    cmd = ['mv', tmp_pcap, pcap_filepath]
    if subprocess.call(cmd, stdout=print_out) != 0:
        print("Error in moving " + tmp_pcap + " to " + pcap_filepath, file=sys.stderr)


def indicates_wifi_or_rmnet(data):
    """ Given data of a mptcp connection subflow, indicates if comes from wifi or rmnet """
    if data[SADDR].startswith(PREFIX_WIFI_IF) or data[DADDR].startswith(PREFIX_WIFI_IF):
        data[IF] = WIFI
    else:
        data[IF] = RMNET


def detect_ipv4(data):
    """ Given the dictionary of a TCP connection, add the type IPv4 if it is an IPv4 connection """
    saddr = data[SADDR]
    daddr = data[DADDR]
    num_saddr = saddr.split('.')
    num_daddr = daddr.split('.')
    if len(num_saddr) == 4 and len(num_daddr) == 4:
        data[TYPE] = 'IPv4'


def get_date_as_int(pcap_fname):
    """ Return the date of the pcap trace in int (like 20141230)
        If there is no date, return None
    """
    dash_index = pcap_fname.index("-")
    start_index = pcap_fname[:dash_index].rindex("_")
    try:
        return int(pcap_fname[start_index + 1:dash_index])
    except ValueError as e:
        print(str(e) + ": get date as int for " + pcap_fname, file=sys.stderr)
        return None


##################################################
##                    GRAPHS                    ##
##################################################


def log_outliers(aggl_res, remove=False, m=3.0, log_file=sys.stdout):
    """ Print on stderr outliers (value + filename), remove them from aggl_res if remove is True """
    for condition, data_label in aggl_res.iteritems():
        for label, data in data_label.iteritems():
            num_data = [elem[0] for elem in data]
            np_data = np.array(num_data)
            d = np.abs(np_data - np.median(np_data))
            mdev = np.median(d)
            s = d / mdev if mdev else 0.0

            if isinstance(s, float) and s == 0.0:
                aggl_res[condition][label] = num_data
                continue
            new_list = []
            for index in range(0, len(data)):
                if s[index] >= m:
                    print("Outlier " + str(data[index][0]) + " of file " + data[index][1] + "; median = " +
                          str(np.median(np_data)) + ", mstd = " + str(mdev) + " and s = " + str(s[index]), file=log_file)
                    if remove:
                        continue
                new_list.append(data[index][0])
            aggl_res[condition][label] = new_list


def sort_and_aggregate(aggr_list):
    """ Given a list of elements as returned by prepare_datasets_file, return a sorted and
        aggregated list
        List is ordered with elem at index 0, aggregated on elem at index 1 and indicates its source
        with elem at index 2
    """
    offsets = {}
    total = 0
    # Sort list by time
    sorted_list = sorted(aggr_list, key=lambda elem: elem[0])
    return_list = []
    for elem in sorted_list:
        # Manage the case when the flow name is seen for the first time
        if elem[2] in offsets.keys():
            total += elem[1] - offsets[elem[2]]
        else:
            total += elem[1]

        offsets[elem[2]] = elem[1]
        return_list.append([elem[0], total])

    return return_list


# Initialize lock semaphore for matplotlib
# This is needed to avoid race conditions inside matplotlib
plt_lock = threading.RLock()


def critical_plot_line_graph(data, label_names, formatting, xlabel, ylabel, title, graph_filepath, ymin=None, titlesize=20):
    """ Critical part to plot a line graph """
    count = 0
    fig = plt.figure()
    plt.clf()
    # Create plots
    try:
        for dataset in data:
            x_val = [x[0] for x in dataset]
            y_val = [x[1] for x in dataset]
            plt.plot(x_val, y_val, formatting[count], label=label_names[count])
            count += 1

        legend = plt.legend(loc='upper left', shadow=True, fontsize='x-large')
    except ValueError as e:
        print(str(e) + ": create plots: skip " + graph_filepath, file=sys.stderr)
        return

    try:
        # Put a nicer background color on the legend.
        legend.get_frame().set_facecolor('#00FFCC')
    except AttributeError as e:
        # if we have no frame, it means we have no object...
        print(str(e) + ": change legend: skip " + graph_filepath, file=sys.stderr)
        print('label_names: ' + str(label_names), file=sys.stderr)
        print('formatting: ' + str(formatting), file=sys.stderr)
        print('data: ' + str(data), file=sys.stderr)
        return

    fig.suptitle(title, fontsize=titlesize)
    plt.xlabel(xlabel, fontsize=18)
    plt.ylabel(ylabel, fontsize=16)

    if ymin is not None:
        plt.ylim(ymin=ymin)

    try:
        plt.savefig(graph_filepath)
    except:
        print('ERROR when creating graph for ' + graph_filepath, file=sys.stderr)
        print(traceback.format_exc(), file=sys.stderr)
        return

    # Don't forget to clean the plot, otherwise previous ones will be there!
    try:
        plt.clf()
    except KeyError as e:
        print(str(e) + ": when cleaning graph " + graph_filepath, file=sys.stderr)
    plt.close()


def plot_line_graph(data, label_names, formatting, xlabel, ylabel, title, graph_filepath, ymin=None, titlesize=20):
    """ Plot a line graph with data """
    # no data, skip
    pop_index = []
    count = 0
    for dataset in data:
        if not dataset or len(dataset) <= 1:
            # If no data, remove it from dataset and manage label name and formatting
            # number = "One" if len(dataset) == 1 else "No"
            # print(number + " data in dataset; remove it", file=sys.stderr)
            pop_index.append(count)
        count += 1

    for index in reversed(pop_index):
        data.pop(index)
        label_names.pop(index)
        formatting.pop(index)

    if not data:
        print("No data for " + title + ": skip", file=sys.stderr)
        return

    plt_lock.acquire()

    try:
        critical_plot_line_graph(
            data, label_names, formatting, xlabel, ylabel, title, graph_filepath, ymin=ymin, titlesize=titlesize)
    except Exception as e:
        print("UNCATCHED EXCEPTION IN critical_plot_line_graph for " + graph_filepath, file=sys.stderr)
        print(str(e), file=sys.stderr)
        print(traceback.format_exc(), file=sys.stderr)

    plt_lock.release()


def plot_bar_chart(aggl_res, label_names, color, ecolor, ylabel, title, graph_fname):
    """ Plot a bar chart with aggl_res """
    plt_lock.acquire()

    matplotlib.rcParams.update({'font.size': 8})

    # Convert Python arrays to numpy arrays (easier for mean and std)
    for cond, elements in aggl_res.iteritems():
        for label, array in elements.iteritems():
            elements[label] = np.array(array)

    N = len(aggl_res)
    nb_subbars = len(label_names)
    ind = np.arange(N)
    labels = []
    values = {}
    for label_name in label_names:
        values[label_name] = ([], [])

    width = (1.00 / nb_subbars) - (0.1 / nb_subbars)        # the width of the bars
    fig, ax = plt.subplots()

    # So far, simply count the number of connections
    for cond, elements in aggl_res.iteritems():
        labels.append(cond)
        for label_name in label_names:
            values[label_name][0].append(elements[label_name].mean())
            values[label_name][1].append(elements[label_name].std())

    bars = []
    labels_names = []
    zero_bars = []
    count = 0

    for label_name in label_names:
        (mean, std) = values[label_name]
        bar = ax.bar(ind + (count * width), mean, width, color=color[count], yerr=std, ecolor=ecolor[count])
        bars.append(bar)
        zero_bars.append(bar[0])
        labels_names.append(label_name)
        count += 1

    # add some text for labels, title and axes ticks
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.set_xticks(ind + width)
    ax.set_xticklabels(labels)

    # Shrink current axis's height by 10% on the bottom
    box = ax.get_position()
    ax.set_position([box.x0, box.y0 + box.height * 0.1,
                     box.width, box.height * 0.9])

    # Put a legend below current axis
    ax.legend(zero_bars, label_names, loc='upper center', bbox_to_anchor=(0.5, -0.05), fancybox=True, shadow=True,
              ncol=len(zero_bars))

    def autolabel(rects):
        # attach some text labels
        for rect in rects:
            height = rect.get_height()
            ax.text(rect.get_x() + rect.get_width() / 2., 1.05 * height, '%d' % int(height),
                    ha='center', va='bottom')

    for bar in bars:
        autolabel(bar)

    plt.savefig(graph_fname)
    plt.close()

    plt_lock.release()


def plot_cdfs(aggl_res, color, xlabel, base_graph_fname):
    """ Plot all possible CDFs based on aggl_res.
        aggl_res is a dictionary with the structure aggl_res[condition][element] = list of data
        base_graph_fname does not have any extension
        WARNING: this function assumes that the list of elements will remain the same for all conditions
    """
    if len(aggl_res) < 1:
        return

    cond_init = aggl_res.keys()[0]

    for element in aggl_res[cond_init].keys():
        plt.figure()
        plt.clf()
        fig, ax = plt.subplots()

        graph_fname = os.path.splitext(base_graph_fname)[0] + "_cdf_" + element + ".pdf"

        for cond in aggl_res.keys():
            try:
                sample = np.array(sorted(aggl_res[cond][element]))

                ecdf = sm.distributions.ECDF(sample)

                x = np.linspace(min(sample), max(sample))
                y = ecdf(x)
                ax.step(x, y, color=color[aggl_res.keys().index(cond)], label=cond)
            except ZeroDivisionError as e:
                print(str(e))

        # Shrink current axis's height by 10% on the top
        box = ax.get_position()
        ax.set_position([box.x0, box.y0,
                         box.width, box.height * 0.9])

        # Put a legend above current axis
        ax.legend(loc='lower center', bbox_to_anchor=(0.5, 1.05), fancybox=True, shadow=True, ncol=len(aggl_res))

        plt.xlabel(xlabel, fontsize=18)
        plt.savefig(graph_fname)
        plt.close('all')


def plot_cdfs_natural(aggl_res, color, xlabel, base_graph_fname):
    """ Plot all possible CDFs based on aggl_res.
        aggl_res is a dictionary with the structure aggl_res[condition][element] = list of data
        base_graph_fname does not have any extension
        WARNING: this function assumes that the list of elements will remain the same for all conditions
    """
    if len(aggl_res) < 1:
        return

    for cond in aggl_res.keys():
        plt.figure()
        plt.clf()
        fig, ax = plt.subplots()

        graph_fname = os.path.splitext(base_graph_fname)[0] + "_cdf_" + cond + ".pdf"

        for element in aggl_res[cond].keys():
            try:
                sample = np.array(sorted(aggl_res[cond][element]))

                ecdf = sm.distributions.ECDF(sample)

                x = np.linspace(min(sample), max(sample))
                y = ecdf(x)
                ax.step(x, y, color=color[aggl_res[cond].keys().index(element)], label=element)
            except ZeroDivisionError as e:
                print(str(e))

        # Shrink current axis's height by 10% on the top
        box = ax.get_position()
        ax.set_position([box.x0, box.y0,
                         box.width, box.height * 0.9])

        # Put a legend above current axis
        ax.legend(loc='lower center', bbox_to_anchor=(0.5, 1.05), fancybox=True, shadow=True, ncol=len(aggl_res[cond]))

        plt.xlabel(xlabel, fontsize=18)
        plt.savefig(graph_fname)
        plt.close('all')


def plot_cdfs_with_direction(aggl_res, color, xlabel, base_graph_fname):
    """ Plot all possible CDFs based on aggl_res.
        aggl_res is a dictionary with the structure aggl_res[direction][condition][element] = list of data
        WARNING: this function assumes that the list of elements will remain the same for all conditions
    """
    if len(aggl_res) < 1:
        return
    for direction in aggl_res.keys():
        plot_cdfs(aggl_res[direction], color, xlabel, os.path.splitext(base_graph_fname)[0] + '_' + direction)


def scatter_plot(data, xlabel, ylabel, color, sums_dir_exp, base_graph_name):
    """ Plot a scatter plot for each condition inside data (points are for apps)
        base_graph_name is given without extension
    """
    for condition, data_cond in data.iteritems():
        plt.figure()
        plt.clf()

        fig, ax = plt.subplots()

        for app_name, data_app in data_cond.iteritems():
            x_val = [x[0] for x in data_app]
            y_val = [x[1] for x in data_app]
            ax.plot(x_val, y_val, 'o', label=app_name, color=color[app_name])

        identity = np.arange(0, 100000000, 1000000)
        ax.plot(identity, identity, 'k--')
        # Shrink current axis by 20%
        box = ax.get_position()
        ax.set_position([box.x0, box.y0, box.width * 0.8, box.height])

        # Put a legend to the right of the current axis
        ax.legend(loc='center left', bbox_to_anchor=(1, 0.5), fontsize='x-small')
        plt.xlabel(xlabel, fontsize=18)
        plt.ylabel(ylabel, fontsize=16)
        ax.set_yscale('symlog', linthreshy=1)
        ax.set_xscale('symlog', linthreshx=1)
        plt.grid()

        graph_fname = base_graph_name + "_" + condition + ".pdf"
        graph_full_path = os.path.join(sums_dir_exp, graph_fname)

        plt.savefig(graph_full_path)

        plt.clf()
        plt.close('all')


def scatter_plot_with_direction(data, xlabel, ylabel, color, sums_dir_exp, base_graph_name):
    """ Plot a scatter plot for each direction and condition inside data (points are for apps)
    """
    for direction, data_dir in data.iteritems():
        scatter_plot(data_dir, xlabel, ylabel, color, sums_dir_exp, os.path.splitext(base_graph_name)[0] + "_" + direction)
