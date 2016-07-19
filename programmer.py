#!/usr/bin/env python
"""Implementation of Microchip's AN1388 on Linux using UART"""

from __future__ import print_function

import sys
import os

import serial
import argparse
import binascii

__author__ = "Camil Staps, V Govorovski"
__copyright__ = "Copyright 2015, Camil Staps"
__credits__ = ["Camil Staps", 
                "Ganapathi Ramachandra (Microchip Technology Inc.)",
                "Vadim Govorovski (Interface Devices Ltd.)"]
__license__ = "GPL"
__version__ = "0.3"
__maintainer__ = "Camil Staps"
__email__ = "info@camilstaps.nl"
__status__ = "Development"

crc_table = [0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7, 
        0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1c1, 0xf1ef]

_debug_level = 0

def crc16(data):
    """Calculate the CRC-16 for a string"""
    i = 0
    crc = 0
    for c in data:
        i = (crc >> 12) ^ (ord(c) >> 4)
        crc = crc_table[i & 0x0f] ^ (crc << 4)
        i = (crc >> 12) ^ (ord(c) >> 0)
        crc = crc_table[i & 0x0f] ^ (crc << 4)

    return chr(crc & 0xff) + chr((crc >> 8) & 0xff)
#    return chr((crc >> 8) & 0xff) + chr(crc & 0xff)

def parse_args():
    pars = argparse.ArgumentParser()

    pars.add_argument('-u', '--upload', 
            help='Upload file to chip',
            metavar='firmware.hex')
    pars.add_argument('-c', '--check',
            help='Check CRC of a memory block ADDR:SIZE'+
                 ' ADDR - 32 bit start address (hex)'+
                 ' SIZE - 32 bit block length in bytes',
            type=str, default='9d000000:000000ff',
            nargs='?')
            #action='store_true')
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

    pars.add_argument('-t', '--timeout',
            help='Timeout in seconds',
            type=float, default=1.0)

    pars.add_argument('-D', '--debug',
            help='Debug level',
            type=int, default=0)

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
    if _debug_level >= 2:
        print('>', binascii.hexlify(request))
    return len(request)

def read_response(serial, command):
    """Read the response from the serial port"""
    response = ''
    while len(response) < 4 \
          or response[-1] != '\x04' or response[-2]=='\x10':
        r = ser.read(1)
        if len(r) == 0:
            raise IOError('Bootloader response timed out')
        if r == '\x01' or len(response) > 0:
            response += r
    
    if _debug_level >= 2:
        print('<', binascii.hexlify(response))

    if response[0] != '\x01' or response[-1] != '\x04':
        raise IOError('Invalid response from bootloader')

    response = unescape(response[1:-1])

    # Verify SOH, EOT and command fields
    if response[0] != command:
        raise IOError('Unexpected response type from bootloader')
    if crc16(response[:-2]) != response[-2:]:
        raise IOError('Invalid CRC from bootloader')

    return response[1:-2]

def upload(serial, filename): 
    txcount, rxcount, txsize, rxsize = 0, 0, 0, 0
    with open(filename) as f:
        for line in f:
            # Check Intel HEX format
            if len(line) < 7:
                raise IOError('Invalid record format')
            if _debug_level >= 1:
                print(line)
            else:
                sys.stdout.write('.')
                sys.stdout.flush()
            # Convert from ASCII to hexdec
            data = binascii.unhexlify(line[1:-1])
            txsize += send_request(serial, '\x03'+data)
            response = read_response(serial, '\x03')
            rxsize += (len(response)+4)
            txcount += 1
            rxcount += 1
        print('*')
    return (txcount, txsize, rxcount, rxsize)

if __name__ == '__main__':
    args = parse_args()
    _debug_level = args.debug
    ser = serial.Serial(args.port, args.baud, timeout=args.timeout)

    if args.version:
        print('Querying..')
        send_request(ser, '\x01')
        version = read_response(ser, '\x01')
        print('Bootloader version: ' + binascii.hexlify(version))

    if args.erase:
        print('Erasing..')
        send_request(ser, '\x02')
        read_response(ser, '\x02')
        print('Done')

    if args.upload != None:
        print('Uploading..')
        upstats = upload(ser, args.upload)
        print('Transmitted: %d packets (%d bytes), Received: %d packets (%d bytes)' % upstats)
        print('Done')

    if args.check != None:
        print('Verifying..')
        addr, size = args.check.split(':')
        addr, size = addr.zfill(8), size.zfill(8)
        send_request(ser, '\x04'+binascii.unhexlify(addr)[::-1]+
                                 binascii.unhexlify(size)[::-1])
        checksum = read_response(ser, '\04')
        print('CRC @%s[%s]: %s' % (addr, size, binascii.hexlify(checksum)))
        #print('Checking CRC is not yet implemented')

    if args.run:
        print('Run Application')
        send_request(ser, '\x05')
    
    print('Done.')
