#!/usr/bin/env python3

"""
  keyholderd -- multi-user SSH agent

  Copyright 2015-2018 Wikimedia Foundation, Inc.
  Copyright 2015 Ori Livneh <ori@wikimedia.org>
  Copyright 2015 Tyler Cipriani <thcipriani@wikimedia.org>
  Copyright 2018 Faidon Liambotis <faidon@wikimedia.org>

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY CODE, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

"""
import argparse
import base64
import collections
import glob
import grp
import hashlib
import logging
import logging.handlers
import os
import pwd
import socket
import socketserver
import struct
import subprocess
import sys

import yaml

from keyholder.crypto import SshRSAKey, SshEd25519Key
from keyholder.protocol.agent import SshAgentResponseCode
from keyholder.protocol.agent import SshAgentCommand, SshAgentCommandHeader
from keyholder.protocol.agent import SshAgentIdentities
from keyholder.protocol.agent import SshAddIdentity, SshRemoveIdentity
from keyholder.protocol.agent import SshAgentSignRequest
from construct.core import ConstructError

logger = logging.getLogger('keyholder')

# Defined in <socket.h>.
SO_PEERCRED = 17

s_ucred = struct.Struct('2Ii')


class SshAgentProtocolError(OSError):
    """Custom exception class for protocol errors."""


def get_key_fingerprints(key_dir):
    """Look up the key fingerprints for all keys held by keyholder"""
    keymap = {}
    for fname in glob.glob(os.path.join(key_dir, '*.pub')):
        line = subprocess.check_output(
            ['/usr/bin/ssh-keygen', '-lf', fname], universal_newlines=True)
        bits, fingerprint, note = line.split(' ', 2)
        keyfile = os.path.splitext(os.path.basename(fname))[0]
        keymap[keyfile] = fingerprint
    logger.info('Successfully loaded %d key(s)', len(keymap))
    return keymap


def get_key_perms(auth_dir, key_dir):
    """Recursively walk `auth_dir`, loading YAML configuration files."""
    key_perms = {}
    fingerprints = get_key_fingerprints(key_dir)
    for fname in glob.glob(os.path.join(auth_dir, '*.y*ml')):
        with open(fname) as yml:
            try:
                data = yaml.safe_load(yml).items()
            except (yaml.YAMLError, AttributeError):
                logger.warning('Unable to read and parse %s', fname)
                continue

            for group, keys in data:
                if keys is None:
                    continue

                for key in keys:
                    if key not in fingerprints:
                        logger.info('Fingerprint not found for key %s', key)
                        continue
                    fingerprint = fingerprints[key]
                    key_perms.setdefault(fingerprint, set()).add(group)
    return key_perms


class SshAgentServer(socketserver.ThreadingUnixStreamServer):
    """A threaded server that listens on a UNIX domain socket."""

    def __init__(self, server_address, key_perms):
        super().__init__(server_address, SshAgentHandler)
        self.keys = collections.OrderedDict()
        self.key_perms = key_perms

    def handle_error(self, request, client_address):
        exc_type, exc_value = sys.exc_info()[:2]
        logger.exception('Unhandled error: [%s] %s', exc_type, exc_value)
        # respond to the client with an SSH_AGENT_FAILURE
        SshAgentHandler.send_message(request, SshAgentResponseCode.FAILURE)


class SshAgentHandler(socketserver.BaseRequestHandler):
    """This class is responsible for handling an individual connection
    to an SshAgentServer."""

    @staticmethod
    def get_peer_credentials(sock):
        """Return the user and group name of the peer of a UNIX socket."""
        ucred = sock.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, s_ucred.size)
        _, uid, gid = s_ucred.unpack(ucred)
        user = pwd.getpwuid(uid).pw_name
        groups = {grp.getgrgid(gid).gr_name}
        groups.update(g.gr_name for g in grp.getgrall() if user in g.gr_mem)
        return user, groups

    @staticmethod
    def recv_message(sock):
        """Read a message from a socket."""
        head = sock.recv(SshAgentCommandHeader.sizeof(), socket.MSG_WAITALL)
        if len(head) != SshAgentCommandHeader.sizeof():
            return None, b''

        try:
            size = SshAgentCommandHeader.parse(head)
            tail = sock.recv(size, socket.MSG_WAITALL)
            command = SshAgentCommand.parse(head + tail)
        except ConstructError:
            raise SshAgentProtocolError('Invalid message received')

        return command.code, command.message

    @staticmethod
    def send_message(sock, code, message=b''):
        """Send a message on a socket."""
        try:
            command = SshAgentCommand.build({
                'code': code,
                'message': message,
            })
            sock.sendall(command)
        except ConstructError:
            raise SshAgentProtocolError('Cannot construct a valid message')

    def handle(self):
        """Handle client connections and process their commands."""
        while 1:
            code, message = self.recv_message(self.request)
            if code is None:
                return

            method = getattr(self, 'handle_' + code.name.lower(), None)
            if method:
                method(message)
            else:
                self.handle_not_implemented(code)

    def handle_request_identities(self, message):
        """Handle the request identities command, listing all identities."""
        if message:
            raise SshAgentProtocolError('Unexpected data')

        identities = []
        for key in self.server.keys.values():
            identities.append({
                'key_blob': key.key_blob,
                'comment': key.comment,
            })
        self.send_message(self.request, SshAgentResponseCode.IDENTITIES_ANSWER,
                          SshAgentIdentities.build(identities))

    def handle_add_identity(self, message):
        """Handle the add identity command, adding a new key to the agent."""
        try:
            identity = SshAddIdentity.parse(message)
        except ConstructError:
            raise SshAgentProtocolError('Unable to parse identity')

        try:
            # pylint: disable=redefined-variable-type
            if identity.key_type == 'ssh-rsa':
                tup = [getattr(identity.key, t) for t in 'nedpq']
                key = SshRSAKey(tup, identity.key.comment)
            elif identity.key_type == 'ssh-ed25519':
                key = SshEd25519Key(identity.key.enc_a, identity.key.k_enc_a,
                                    identity.key.comment)
            else:
                logger.warning('Unsupported key type %s', identity.key_type)
                self.send_message(self.request, SshAgentResponseCode.FAILURE)
                return
        except TypeError:
            logger.warning('Cannot add key to agent, invalid key')
            self.send_message(self.request, SshAgentResponseCode.FAILURE)
        else:
            self.server.keys[key.fingerprint] = key
            logger.info('Successfully added key %s', key.comment)
            self.send_message(self.request, SshAgentResponseCode.SUCCESS)

    def handle_remove_identity(self, message):
        """Handle the remove identity command, removing a key from the
        agent."""
        try:
            identity = SshRemoveIdentity.parse(message)
        except ConstructError:
            raise SshAgentProtocolError('Unable to parse identity')

        key_digest = (b'SHA256:' + base64.b64encode(hashlib.sha256(
            identity.key_blob).digest()).rstrip(b'=')).decode('utf-8')

        try:
            comment = self.server.keys[key_digest].comment
            del self.server.keys[key_digest]
            logger.info('Successfully removed key %s', comment)
            self.send_message(self.request, SshAgentResponseCode.SUCCESS)
        except KeyError:
            self.send_message(self.request, SshAgentResponseCode.FAILURE)

    def handle_remove_all_identities(self, message):
        """Handle the remove all identities command, removing all keys from
        the agent."""
        if message:
            raise SshAgentProtocolError('Unexpected data')

        self.server.keys.clear()
        logger.info('Removed all keys')
        self.send_message(self.request, SshAgentResponseCode.SUCCESS)

    def handle_sign_request(self, message):
        """Handle a sign request command."""
        try:
            request = SshAgentSignRequest.parse(message)
        except ConstructError:
            raise SshAgentProtocolError('Invalid sign request received')

        key_digest = (b'SHA256:' + base64.b64encode(hashlib.sha256(
            request.key_blob).digest()).rstrip(b'=')).decode('utf-8')

        try:
            key = self.server.keys[key_digest]
        except KeyError:
            logger.info('Refusing agent sign request, key was not found')
            self.send_message(self.request, SshAgentResponseCode.FAILURE)
            return

        user, groups = self.get_peer_credentials(self.request)
        if groups & self.server.key_perms.get(key_digest, set()):
            logger.info('Granting agent sign request for user %s', user)
            signature = key.sign(request.data, request.flags)
            self.send_message(self.request, SshAgentResponseCode.SIGN_RESPONSE,
                              signature)
        else:
            logger.info('Refusing agent sign request for user %s', user)
            self.send_message(self.request, SshAgentResponseCode.FAILURE)

    def handle_not_implemented(self, code):
        """Catch all for not implement commands."""
        logger.debug('Request type %s not implemented', code.name)
        self.send_message(self.request, SshAgentResponseCode.FAILURE)


def parse_args(argv):
    """Parse and return the parsed command line arguments."""
    parser = argparse.ArgumentParser(
        prog='keyholderd',
        description='multi-user SSH agent',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Debug mode: log to stdout and be more verbose',
    )
    parser.add_argument(
        '--bind',
        default='/run/keyholder/agent.sock',
        help='Bind the agent to the domain socket at this address'
    )
    parser.add_argument(
        '--key-dir',
        default='/etc/keyholder.d',
        help='directory with SSH keys'
    )
    parser.add_argument(
        '--auth-dir',
        default='/etc/keyholder-auth.d',
        help='directory with YAML configuration files'
    )
    return parser.parse_args(argv)


def setup_logging(debug):
    """Setup logging format and level."""
    if debug:
        logger.setLevel(logging.DEBUG)
        stream_handler = logging.StreamHandler()
        fmt = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
        stream_handler.setFormatter(fmt)
        logger.addHandler(stream_handler)
    else:
        logger.setLevel(logging.INFO)
        syslog_handler = logging.handlers.SysLogHandler(
            address='/dev/log',
            facility='auth',
        )
        fmt = logging.Formatter('%(name)s[%(process)d]: %(message)s')
        fmt.formatException = lambda x: ''
        syslog_handler.setFormatter(fmt)
        logger.addHandler(syslog_handler)


def main(argv=None):
    """Main entry point; runs forever."""
    args = parse_args(argv)
    setup_logging(args.debug)

    perms = get_key_perms(args.auth_dir, args.key_dir)
    logger.info('Initialized and serving requests')

    server = SshAgentServer(args.bind, perms)

    try:
        server.serve_forever()
    except (SystemExit, KeyboardInterrupt):
        logger.info('Shutting down')
    server.server_close()


if __name__ == '__main__':
    main()
