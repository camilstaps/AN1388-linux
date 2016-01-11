#!/usr/bin/env python
"""Implementation of Microchip's AN1388 on Linux using UART"""

from __future__ import print_function

import sys
import os

import serial
import argparse
import binascii

__author__ = "Camil Staps"
__copyright__ = "Copyright 2015, Camil Staps"
__credits__ = ["Camil Staps", 
                "Ganapathi Ramachandra (Microchip Technology Inc.)"]
__license__ = "GPL"
__version__ = "0.1"
__maintainer__ = "Camil Staps"
__email__ = "info@camilstaps.nl"
__status__ = "Development"

crc_table = [0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7, 
        0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1c1, 0xf1ef]

def crc16(data):
    """Calculate the CRC-16 for a string"""
    i = 0
    crc = 0
    for c in data:
        i = (crc >> 12) ^ (ord(c) >> 4)
        crc = crc_table[i & 0x0f] ^ (crc << 4)
        i = (crc >> 12) ^ (ord(c) >> 0)
        crc = crc_table[i & 0x0f] ^ (crc << 4)

    return chr((crc >> 8) & 0xff) + chr(crc & 0xff)

def parse_args():
    pars = argparse.ArgumentParser()

    pars.add_argument('-u', '--upload', 
            help='Upload file to chip',
            metavar='firmware.hex')
    pars.add_argument('-c', '--check',
            help='Check CRC',
            metavar='firmware.hex',
            nargs='?')
    pars.add_argument('-e', '--erase',
            help='Erase before upload',
            action='store_true')
    pars.add_argument('-r', '--run',
            help='Run after upload',
            action='store_true')

    pars.add_argument('-v', '--version', 
            help='Read bootloader version',
            action='store_true')

    pars.add_argument('-p', '--port',
            help='Serial port to use',
            required=True)
    pars.add_argument('-b', '--baud',
            help='Baudrate to the bootloader',
            type=int, default=115200)

    pars.add_argument('--my-version', 
            action='version', 
            version='%(prog)s ' + __version__)

    return pars.parse_args()

def escape(data):
    # Escape control characters
    data = data.replace('\x10', '\x10\x10')
    data = data.replace('\x01', '\x10\x01')
    data = data.replace('\x04', '\x10\x04')
    return data

def unescape(data):
    escape = False
    record = ''
    for c in list(data):
        if escape:
            record += c
            escape = False
        elif c == '\x10':
            escape = True
        else:
            record += c
    return record

def send_request(serial, command, wait=True):
    """Send a command over a serial port"""
    command = escape(command)

    # Build and send request
    request = '\x01' + command + escape(crc16(command)) + '\x04'
    serial.write(request)

def read_response(serial, command):
    """Read the response from the serial port"""
    response = ''
    r = ser.read(1)
    while r != '\x01':
        r = ser.read(1)
    while r != '\x04' or len(response) == 0 or response[-1] == '\x10':
        response += r
        r = ser.read(1)
    response += r

    if response[0] != '\x01' or response[-1] != '\x04':
        raise IOError('Invalid response from bootloader')

    response = unescape(response[1:-1])

    # Verify SOH, EOT and command fields
    if response[0] != command:
        raise IOError('Invalid response from bootloader')
    if crc16(response[:-2]) != response[-2:]:
        raise IOError('Invalid CRC from bootloader')

    response = response[1:-2]

    return response

def upload(serial, filename):
    with open(filename) as f:
        serial.write('\x01\x03')
        data = ''
        for line in f:
            data += line
            serial.write(escape(line))
        serial.write(escape(crc16(data)))
        serial.write('\x04')

if __name__ == '__main__':
    args = parse_args()

    ser = serial.Serial(args.port, args.baud, timeout=1)

    if args.version:
        send_request(ser, '\x01')
        version = read_response(ser, '\x01')
        print('Bootloader version: ' + binascii.hexlify(version))

    if args.erase:
        send_request(ser, '\x02')
        read_response(ser, '\x02')

    if args.upload != None:
        upload(ser, args.upload)
        read_response(ser, '\x03')

    if args.check:
        print('Checking CRC is not yet implemented')

    if args.run:
        send_request(ser, '\x05')

