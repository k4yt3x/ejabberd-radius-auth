#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Name: Ejabberd RADIUS Authentication Script
Dev: K4YT3X
Date Created: July 14, 2018
Last Modified: September 30, 2018

Licensed under the GNU General Public License Version 3 (GNU GPL v3),
    available at: https://www.gnu.org/licenses/gpl-3.0.txt
(C) 2018 K4YT3X

Part of the script used iltl's code
as a reference. (Contact: iltl@free.fr)

Description: An authentication script for ejabberd
"""
from pyrad.client import Client
from pyrad.dictionary import Dictionary
import pyrad.packet
import struct
import sys
import syslog
import traceback

RADIUS_SERVER = 'auth.radius.server'  # RADIUS server address
RADIUS_PASSWORD = 'radiuspassword'  # RADIUS authentication password


class RadiusSession:
    """
    Class that controls a RADIUS authentication
    session. Responsible for communicating with
    the RADIUS server.
    """

    def __init__(self, server_addr, secret):
        """ Initialize the connection
        """
        self.server_addr = server_addr
        self.nas_identifier = self.server_addr
        self.secret = secret.encode()
        self.server = Client(server=self.server_addr, secret=self.secret,
                             dict=Dictionary('/etc/ejabberd/dictionary'))

    def auth(self, username, password):
        """ Request for authentication

        Returns True if successful, else False.
        """
        request = self.server.CreateAuthPacket(
            code=pyrad.packet.AccessRequest, User_Name=username, NAS_Identifier=self.nas_identifier)
        request['User-Password'] = request.PwCrypt(password)

        reply = self.server.SendPacket(request)
        if reply.code == pyrad.packet.AccessAccept:
            return True
        else:
            return False


class EjabberdInputError(Exception):
    """ Raise this error when ejabberd sends
    invalid requests.
    """
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


def ejabberd_in():
    """ Get ejabberd input
    """
    input_length = sys.stdin.read(2)
    if len(input_length) is not 2:
        raise EjabberdInputError('Wrong input from ejabberd!')
    (size,) = struct.unpack('>h', input_length.encode())
    income = sys.stdin.read(size).split(':', 4)
    return income


def ejabberd_out(bool):
    """ Respond to ejabberd authentication request
    """
    token = gen_ejabberd_answer(bool)
    sys.stdout.write(token.decode())
    sys.stdout.flush()


def gen_ejabberd_answer(bool):
    """ Generate an ejabberd answer
    """
    answer = 0
    if bool:
        answer = 1
    token = struct.pack('>hh', 2, answer)
    return token


radius_session = RadiusSession(RADIUS_SERVER, RADIUS_PASSWORD)
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
