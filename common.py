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
import Gnuplot
import pickle
import subprocess
import sys

Gnuplot.GnuplotOpts.default_term = 'pdf'

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
##               COMMON CONSTANTS               ##
##################################################

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

# IPv4 localhost address
LOCALHOST_IPv4 = '127.0.0.1'
# Port number of RedSocks
PORT_RSOCKS = '8123'
# Prefix of the Wi-Fi interface IP address
PREFIX_WIFI_IF = '192.168.'
# Size of Latin alphabet
SIZE_LAT_ALPH = 26

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
            print(directory + " is a file: stop")
    else:
        os.makedirs(directory)


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


##################################################
##                   PCAP                       ##
##################################################


def copy_remain_pcap_file(pcap_fname, print_out=sys.stdout):
    """ Given a pcap filename, return the filename of a copy, used for correction of traces """
    remain_pcap_fname = pcap_fname[:-5] + "__rem.pcap"
    cmd = ['cp', pcap_fname, remain_pcap_fname]
    if subprocess.call(cmd, stdout=print_out) != 0:
        print("Error when copying " + pcap_fname + ": skip tcp correction", file=sys.stderr)
        return None
    return remain_pcap_fname


def save_connections(pcap_fname, stat_dir_exp, connections):
    """ Using the name pcap_fname, save the statistics about connections """
    stat_fname = os.path.join(
        stat_dir_exp, os.path.basename(pcap_fname)[:-5])
    try:
        stat_file = open(stat_fname, 'w')
        pickle.dump(connections, stat_file)
        stat_file.close()
    except IOError as e:
        print(str(e) + ': no stat file for ' + pcap_fname, file=sys.stderr)


def clean_loopback_pcap(pcap_fname, print_out=sys.stdout):
    """ Remove noisy traffic (port 1984), see netstat """
    tmp_pcap = "tmp.pcap"
    cmd = ['tshark', '-Y', '!(tcp.dstport==1984||tcp.srcport==1984)&&!((ip.src==127.0.0.1)&&(ip.dst==127.0.0.1))', '-r',
           pcap_fname, '-w', tmp_pcap, '-F', 'pcap']
    if subprocess.call(cmd, stdout=print_out) != 0:
        print("Error in cleaning " + pcap_fname, file=sys.stderr)
        return
    cmd = ['mv', tmp_pcap, pcap_fname]
    if subprocess.call(cmd, stdout=print_out) != 0:
        print("Error in moving " + tmp_pcap + " to " + pcap_fname, file=sys.stderr)


##################################################
##             CONNECTION RELATED               ##
##################################################


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
