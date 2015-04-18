#! /usr/bin/env python

# Copyright (C) 2015
# Author     : Quentin De Coninck (quentin.deconinck@student.uclouvain.be)
# Created on : Apr 10, 2015

# An simple script to parse socks commands
# This tool uses dpkt library for packet parsing and tshark to filter socks packets

from __future__ import print_function

import argparse
import common as co
import dpkt
import hashlib
import os
import string
import struct
import subprocess
import sys

PASSWORD = "password"
if os.path.isfile('config.py'):
    import config as conf
    PASSWORD = conf.PASSWORD

# The default input directory (with .pcap and .pcap.gz files)
DEF_IN_DIR = 'input'
# The default traces directory (kind of temparary directory, where traces
# will be stored)
DEF_TRACE_DIR = 'traces'
DEF_PORTS_DIR = 'ports'

parser = argparse.ArgumentParser(
    description="Analyze pcap files to detect popular ports number contacted")
parser.add_argument("-i",
                    "--input", help="input directory/file of the (possibly compressed) pcap files", default=DEF_IN_DIR)
parser.add_argument("-t",
                    "--trace", help="temporary directory that will be used to store uncompressed "
                    + "pcap files", default=DEF_TRACE_DIR)
parser.add_argument("-p", "--pcap",
                    help="analyze only pcap files containing the given string (default any, wlan0 and rmnet0)",
                    nargs="+", default=["_" + co.DEF_IFACE + ".", "_wlan0.", "_rmnet0."])
parser.add_argument("-P",
                    "--ports", help="directory where the ports results will be stored", default=DEF_PORTS_DIR)

args = parser.parse_args()

in_dir_exp = os.path.abspath(os.path.expanduser(args.input))
# ~/graphs -> /home/mptcp/graphs_lo ; ../graphs/ -> /home/mptcp/graphs_lo
trace_dir_exp = co.get_dir_from_arg(args.trace, args.pcap[0])
ports_dir_exp = co.get_dir_from_arg(args.ports, args.pcap[0])

if os.path.isdir(in_dir_exp):
    # add the basename of the input dir
    base_dir = os.path.basename(in_dir_exp)  # 20150215-013001_d8cac271ad6d544930b0e804383c19378ed4908c
    parent_dir = os.path.basename(os.path.dirname(in_dir_exp))  # TCPDump or TCPDump_bad_simulation
    trace_dir_exp = os.path.join(trace_dir_exp, parent_dir, base_dir)
    ports_dir_exp = os.path.join(ports_dir_exp, parent_dir, base_dir)

print_out = sys.stdout

co.check_directory_exists(ports_dir_exp)

class TSharkError(Exception):
    pass

def tshark_filter(condition, src_path, dst_path, print_out=sys.stderr):
    """ Filter src_path using the condition and write the result to dst_path
        Raise a TSharkError in case of failure
    """
    cmd = ['tshark', '-r', src_path, '-Y', condition, '-w', dst_path]
    if subprocess.call(cmd, stdout=print_out) != 0:
        raise TSharkError("Error with condition " + condition + " for source " + src_path + " and destination "
                             + dst_path)


def uncompress_file(filename, dirpath):
    if any(match in filename for match in args.pcap):
        # Files from UI tests will be compressed; unzip them
        if filename.endswith('.pcap.gz'):
            output_filepath = os.path.join(trace_dir_exp, filename[:-3])
            # if args.not_correct:
            #     return output_filepath
            if os.path.exists(output_filepath):
                print("Do no uncompress file: already exists " + filename, file=sys.stderr)
                return output_filepath
            else:
                print("Uncompressing " + filename + " to " + trace_dir_exp, file=print_out)
                output = open(output_filepath, 'w')
                cmd = ['gunzip', '-c', '-9', os.path.join(dirpath, filename)]
                if args.keep:
                    cmd.insert(1, '-k')
                if subprocess.call(cmd, stdout=output) != 0:
                    print("Error when uncompressing " + filename, file=sys.stderr)
                    output.close()
                else:
                    output.close()
                    return output_filepath
        elif filename.endswith('.pcap'):
            output_filepath = os.path.join(trace_dir_exp, filename)
            # if args.not_correct:
            #     return output_filepath
            if os.path.exists(output_filepath):
                print("Do no copy file: already exists " + filename, file=sys.stderr)
                return output_filepath
            else:
                # Move the file to out_dir_exp
                print("Copying " + filename + " to " + trace_dir_exp, file=print_out)
                cmd = ['cp', os.path.join(dirpath, filename), output_filepath]
                if subprocess.call(cmd, stdout=print_out) != 0:
                    print("Error when moving " + filename, file=sys.stderr)
                else:
                    return output_filepath
        else:
            print(filename + ": not in a valid format, skipped", file=sys.stderr)
    return False


def add_if_valid(list, item):
    if item:
        list.append(item)

pcap_list = []
co.check_directory_exists(trace_dir_exp)
if os.path.isdir(in_dir_exp):
    for dirpath, dirnames, filenames in os.walk(in_dir_exp):
        for filename in filenames:
            add_if_valid(pcap_list, uncompress_file(filename, dirpath))
else:
    add_if_valid(pcap_list, uncompress_file(os.path.basename(in_dir_exp),
                                            os.path.dirname(in_dir_exp)))

pcap_list_len = len(pcap_list)


def get_table(key):
    m = hashlib.md5()
    m.update(key)
    s = m.digest()
    a, b = struct.unpack('<QQ', s)
    table = string.maketrans(b'', b'')
    table = [table[i: i + 1] for i in range(len(table))]
    for i in range(1, 1024):
        table.sort(key=lambda x: int(a % (ord(x) + i)))
    return table, string.maketrans(b''.join(table), string.maketrans(b'', b''))

def hexa(s):
    return int(s, 16)

def decode(s):
    result = []
    for i in list(s):
        result.append(decrypt_table[ord(i)])
    return result

def encode(s):
    result = []
    for i in s.split():
        result.append(encrypt_table[hexa(i)])
    return result

orig_table = string.maketrans(b'', b'')
orig_table = [orig_table[i: i + 1] for i in range(len(orig_table))]
orig_table_decrypt = string.maketrans(b''.join(orig_table), string.maketrans(b'', b''))

encrypt_table, decrypt_table = get_table(bytes(PASSWORD))

def add_port(cmd, ports):
    port = ord(cmd[5]) * 256 + ord(cmd[6])
    print(port)
    if port not in ports:
        ports[port] = 1
    else:
        ports[port] += 1

def process_pcap(pcap_filepath, ports):
    # condition = "tcp.len==7"
    # tshark_filter(condition, pcap_filepath, pcap_filtered_filepath)
    file = open(pcap_filepath)
    try:
        pcap = dpkt.pcap.Reader(file)
        for ts, data in pcap:
            eth = dpkt.ethernet.Ethernet(data)
            ip = eth.data
            tcp = ip.data
            if len(tcp.data) == 7:
                crypted_socks_cmd = tcp.data
                decrypted_socks_cmd = decode(crypted_socks_cmd)
                if decrypted_socks_cmd[0] == b'\x01': # Connect
                    add_port(decrypted_socks_cmd, ports)
    except Exception as e:
        print(e)

    file.close()

if __name__ == "__main__":
    for pcap_filepath in pcap_list:
        ports = {}
        process_pcap(pcap_filepath, ports)
        co.save_data(pcap_filepath, ports_dir_exp, ports)
