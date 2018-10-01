#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Name: Ejabberd RADIUS Authentication Script
Dev: K4YT3X
Date Created: July 14, 2018
Last Modified: July 18, 2018

Licensed under the GNU General Public License Version 3 (GNU GPL v3),
    available at: https://www.gnu.org/licenses/gpl-3.0.txt
(C) 2018 K4YT3X

Description: An authentication script for ejabberd
"""
from pyrad.client import Client
from pyrad.dictionary import Dictionary
import pyrad.packet
import struct
import sys
import syslog
import traceback


class RadiusSession:

    def __init__(self, server_addr, secret):
        self.server_addr = server_addr
        self.nas_identifier = self.server_addr
        self.secret = secret.encode()
        self.server = Client(server=self.server_addr, secret=self.secret,
                             dict=Dictionary('/etc/ejabberd/dictionary'))

    def auth(self, username, password):
        request = self.server.CreateAuthPacket(
            code=pyrad.packet.AccessRequest, User_Name=username, NAS_Identifier=self.nas_identifier)
        request['User-Password'] = request.PwCrypt(password)

        reply = self.server.SendPacket(request)
        if reply.code == pyrad.packet.AccessAccept:
            return True
        else:
            return False


class EjabberdInputError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


def ejabberd_in():
    input_length = sys.stdin.read(2)
    if len(input_length) is not 2:
        raise EjabberdInputError('Wrong input from ejabberd!')
    (size,) = struct.unpack('>h', input_length.encode())
    income = sys.stdin.read(size).split(':', 4)
    return income


def ejabberd_out(bool):
    token = gen_ejabber_answer(bool)
    sys.stdout.write(token.decode())
    sys.stdout.flush()


def gen_ejabber_answer(bool):
    answer = 0
    if bool:
        answer = 1
    token = struct.pack('>hh', 2, answer)
    return token


radius_session = RadiusSession('auth.realm.re', 'heycaniusetheremotedbplz')
syslog.syslog('Python ejabberd RADIUS authenticator initialized')

while True:

    try:
        ejab_request = ejabberd_in()
    except EOFError:
        break
    except Exception as e:
        syslog.syslog(traceback.format_exc())
        raise

    op_result = False
    try:
        if ejab_request[0] == "auth":
            op_result = radius_session.auth(ejab_request[1], ejab_request[3])
    except Exception:
        syslog.syslog(traceback.format_exc())

    ejabberd_out(op_result)
    syslog.syslog("successful" if op_result else "unsuccessful")

syslog.syslog('Script Terminating')
