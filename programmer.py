#!/usr/bin/env python
"""Implementation of Microchip's AN1388 on Linux using UART"""

from __future__ import print_function

import sys

import serial
import argparse
import binascii

__author__ = "Camil Staps, V Govorovski"
__copyright__ = "Copyright 2015, Camil Staps"
__credits__ = [
    "Camil Staps",
    "Ganapathi Ramachandra (Microchip Technology Inc.)",
    "Vadim Govorovski (Interface Devices Ltd.)"]
__license__ = "GPL"
__version__ = "0.2"
__maintainer__ = "Camil Staps"
__email__ = "info@camilstaps.nl"
__status__ = "Development"

CRC_TABLE = [
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
    0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1c1, 0xf1ef]

DEBUG_LEVEL = 0

def crc16(data):
    """Calculate the CRC-16 for a string"""
    i = 0
    crc = 0
    for byte in data:
        i = (crc >> 12) ^ (ord(byte) >> 4)
        crc = CRC_TABLE[i & 0x0f] ^ (crc << 4)
        i = (crc >> 12) ^ (ord(byte) >> 0)
        crc = CRC_TABLE[i & 0x0f] ^ (crc << 4)

    return chr(crc & 0xff) + chr((crc >> 8) & 0xff)

def parse_args():
    """Parse command line arguments"""
    pars = argparse.ArgumentParser()

    pars.add_argument(
        '-u', '--upload',
        help='Upload file to chip',
        metavar='firmware.hex')
    pars.add_argument(
        '-c', '--check',
        help='Check CRC',
        metavar='firmware.hex',
        nargs='?')
    pars.add_argument(
        '-e', '--erase',
        help='Erase before upload',
        action='store_true')
    pars.add_argument(
        '-r', '--run',
        help='Run after upload',
        action='store_true')

    pars.add_argument(
        '-v', '--version',
        help='Read bootloader version',
        action='store_true')

    pars.add_argument(
        '-p', '--port',
        help='Serial port to use',
        required=True)
    pars.add_argument(
        '-b', '--baud',
        help='Baudrate to the bootloader',
        type=int, default=115200)

    pars.add_argument(
        '-D', '--debug',
        help='Debug level',
        type=int, default=0)

    pars.add_argument(
        '--my-version',
        action='version',
        version='%(prog)s ' + __version__)

    return pars.parse_args()

def escape(data):
    """Escape control characters"""
    data = data.replace('\x10', '\x10\x10')
    data = data.replace('\x01', '\x10\x01')
    data = data.replace('\x04', '\x10\x04')
    return data

def unescape(data):
    """Inverse of escape"""
    escaping = False
    record = ''
    for byte in list(data):
        if escaping:
            record += byte
            escaping = False
        elif byte == '\x10':
            escaping = True
        else:
            record += byte
    return record

def send_request(port, command):
    """Send a command over a serial port"""
    command = escape(command)

    # Build and send request
    request = '\x01' + command + escape(crc16(command)) + '\x04'
    port.write(request)
    if DEBUG_LEVEL >= 2:
        print('>', binascii.hexlify(request))

def read_response(port, command):
    """Read the response from the serial port"""
    response = ''
    byte = port.read(1)
    if byte is None:
        raise IOError('Response timed out')
    while byte != '\x01':
        byte = port.read(1)
    while byte != '\x04' or len(response) == 0 or response[-1] == '\x10':
        response += byte
        byte = port.read(1)
    response += byte

    if DEBUG_LEVEL >= 2:
        print('<', binascii.hexlify(response))

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

def upload(port, filename):
    """Upload a hexfile"""
    with open(filename) as hexfile:
        for line in hexfile:
            # Check Intel HEX format
            if len(line) < 7:
                raise IOError('Invalid record format')
            if DEBUG_LEVEL >= 1:
                print(line)
            else:
                sys.stdout.write('.')
                sys.stdout.flush()
            # Convert from ASCII to hexdec
            data = binascii.unhexlify(line[1:-1])
            send_request(port, '\x03' + data)
            read_response(port, '\x03')

def main():
    """Main programmer function"""
    global DEBUG_LEVEL # pylint: disable=global-statement

    args = parse_args()
    DEBUG_LEVEL = args.debug
    ser = serial.Serial(args.port, args.baud, timeout=1)

    if args.version:
        print('Querying..')
        send_request(ser, '\x01')
        version = read_response(ser, '\x01')
        print('Bootloader version: ' + binascii.hexlify(version))

    if args.erase:
        print('Erasing..')
        send_request(ser, '\x02')
        read_response(ser, '\x02')

    if args.upload != None:
        print('Uploading..')
        upload(ser, args.upload)

    if args.check:
        print('Checking CRC is not yet implemented.')

    if args.run:
        print('Running application..')
        send_request(ser, '\x05')

    print('Done.')

if __name__ == '__main__':
    main()
