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
import ctypes
import grp
import hashlib
import logging
import logging.handlers
import os
import pathlib
import pwd
import socket
import socketserver
import struct
import subprocess
import sys
import yaml

from keyholder.crypto import SshRSAKey, SshEd25519Key, SshLock
from keyholder.protocol.agent import SshAgentRequest, SshAgentRequestHeader
from keyholder.protocol.agent import SshAgentResponse, SshAgentResponseCode
from keyholder.protocol.types import SshRequestPublicKeySignature
from construct.core import ConstructError

AGENT_MAX_LEN = 256*1024
SO_PEERCRED = 17
MCL_CURRENT = 1
MCL_FUTURE = 2

logger = logging.getLogger('keyholder')  # pylint: disable=invalid-name


class SshAgentProtocolError(OSError):
    """Custom exception class for protocol errors."""


def get_key_fingerprints(key_dir):
    """Look up the key fingerprints for all keys held by keyholder"""
    keymap = {}
    if not key_dir.is_dir():
        logger.warning('%s is not a directory', key_dir)

    for fname in key_dir.glob('*.pub'):
        line = subprocess.check_output(
            ['/usr/bin/ssh-keygen', '-lf', str(fname)],
            universal_newlines=True)
        _, fingerprint, _ = line.split(' ', 2)
        keymap[fname.stem] = fingerprint
    logger.info('Successfully loaded %d key(s)', len(keymap))
    return keymap


def get_key_perms(auth_dir, key_dir):
    """Recursively walk `auth_dir`, loading YAML configuration files."""
    key_perms = {}
    fingerprints = get_key_fingerprints(key_dir)
    if not auth_dir.is_dir():
        logger.warning('%s is not a directory', auth_dir)

    for fname in auth_dir.glob('*.y*ml'):
        try:
            data = yaml.safe_load(fname.read_bytes()).items()
        except OSError:
            logger.warning('Unable to read %s', str(fname))
            continue
        except (yaml.YAMLError, AttributeError):
            logger.warning('Unable to parse %s', str(fname))
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
        self.lock = SshLock()

    def server_close(self):
        super().server_close()
        # remove the stale socket that's left behind
        sock = pathlib.Path(self.server_address)
        if sock.is_socket():
            sock.unlink()

    def handle_error(self, request, client_address):
        exc_type, exc_value = sys.exc_info()[:2]
        logger.exception('Unhandled error: [%s] %s', exc_type, exc_value)


class SshAgentHandler(socketserver.StreamRequestHandler):
    """This class is responsible for handling an individual connection
    to an SshAgentServer."""

    @staticmethod
    def get_peer_credentials(sock):
        """Return the user and group name of the peer of a UNIX socket."""
        s_ucred = struct.Struct('2Ii')
        ucred = sock.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, s_ucred.size)
        _, uid, gid = s_ucred.unpack(ucred)
        user = pwd.getpwuid(uid).pw_name
        groups = {grp.getgrgid(gid).gr_name}
        groups.update(g.gr_name for g in grp.getgrall() if user in g.gr_mem)
        return user, groups

    def recv_request(self):
        """Receive and parse a request."""
        size = SshAgentRequestHeader.sizeof()
        head = self.rfile.read(size)
        if len(head) != size:
            raise EOFError

        try:
            size = SshAgentRequestHeader.parse(head)
            tail = self.rfile.read(size)
            if len(tail) != size:
                raise EOFError
            if size > AGENT_MAX_LEN:
                raise SshAgentProtocolError('Received message too big')
            request = SshAgentRequest.parse(head + tail)
        except ConstructError:
            raise SshAgentProtocolError('Invalid message received')

        return request.code, request.message

    def send_response(self, code, message=b''):
        """Build and send a response."""
        try:
            command = SshAgentResponse.build({
                'code': code,
                'message': message,
            })
        except ConstructError:
            raise SshAgentProtocolError('Cannot construct a valid message')

        if len(command) > AGENT_MAX_LEN:
            raise SshAgentProtocolError('Constructed message too big')

        try:
            self.wfile.write(command)
            self.wfile.flush()
        except (OSError, ValueError):
            logger.info('Response write failed')

    def is_superuser(self):
        """Returns True if the requesting user is a superuser."""
        return self.user == 'root'

    def is_allowed(self, key_digest):
        """Returns True if self.user is allowed to operate on key_digest."""
        if self.server.lock.is_locked():
            return False

        if self.is_superuser():
            return True

        allowed_groups = self.server.key_perms.get(key_digest, set())
        return self.groups & allowed_groups

    def setup(self):
        """Retrieve the requesting user and their groups."""
        super().setup()
        self.user, self.groups = self.get_peer_credentials(self.request)

    def handle(self):
        """Handle client connections, potentially with multiple requests
        each."""
        while True:
            try:
                self.handle_one()
            except EOFError:
                break

    def handle_one(self):
        """Handle a single client request."""
        # first, receive and decode the command
        try:
            code, message = self.recv_request()
        except SshAgentProtocolError as exc:
            logger.info('Invalid request received: %s', exc, exc_info=True)
            return self.send_response(SshAgentResponseCode.FAILURE)

        # then, route to the appropriate method, or handle_not_implemented
        method = getattr(self, 'handle_' + code.name.lower(), None)
        try:
            if method:
                response = method(message)
            else:
                response = self.handle_not_implemented(code)
        except SshAgentProtocolError as exc:
            logger.info('Failure while processing: %s', exc, exc_info=True)
            return self.send_response(SshAgentResponseCode.FAILURE)

        # if a single code (e.g. SUCCESS or FAILURE) was returned, convert into
        # a (code, message) response tuple, but with an empty message
        if isinstance(response, SshAgentResponseCode):
            response = (response,)  # pylint: disable=redefined-variable-type

        # finally, build and send the appropriate response
        try:
            return self.send_response(*response)
        except (SshAgentProtocolError, OSError) as exc:
            logger.exception('Failure while building response: %s', exc)
            return self.send_response(SshAgentResponseCode.FAILURE)

    def handle_request_identities(self, _):
        """Handle the request identities command, listing all identities."""
        identities = []
        for fingerprint, key in self.server.keys.items():
            if not self.is_allowed(fingerprint):
                continue

            identities.append({
                'key_blob': key.key_blob,
                'comment': key.comment,
            })
        return (SshAgentResponseCode.IDENTITIES_ANSWER, identities)

    def handle_add_identity(self, identity):
        """Handle the add identity command, adding a new key to the agent."""
        if not self.is_superuser():
            logger.info('User %s not allowed to add a key', self.user)
            return SshAgentResponseCode.FAILURE

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
                return SshAgentResponseCode.FAILURE
        except TypeError:
            logger.warning('Cannot add key to agent, invalid key')
            return SshAgentResponseCode.FAILURE
        else:
            self.server.keys[key.fingerprint] = key
            logger.info('Successfully added key %s', key.comment)
            return SshAgentResponseCode.SUCCESS

    def handle_remove_identity(self, identity):
        """Handle the remove identity command, removing a key from the
        agent."""
        if not self.is_superuser():
            logger.info('User %s not allowed to remove keys', self.user)
            return SshAgentResponseCode.FAILURE

        key_digest = (b'SHA256:' + base64.b64encode(hashlib.sha256(
            identity.key_blob).digest()).rstrip(b'=')).decode('utf-8')

        try:
            comment = self.server.keys[key_digest].comment
            del self.server.keys[key_digest]
            logger.info('Successfully removed key %s', comment)
            return SshAgentResponseCode.SUCCESS
        except KeyError:
            return SshAgentResponseCode.FAILURE

    def handle_remove_all_identities(self, _):
        """Handle the remove all identities command, removing all keys from
        the agent."""
        if not self.is_superuser():
            logger.info('User %s not allowed to remove keys', self.user)
            return SshAgentResponseCode.FAILURE

        self.server.keys.clear()
        logger.info('Removed all keys')
        return SshAgentResponseCode.SUCCESS

    def handle_sign_request(self, request):
        """Handle a sign request command."""
        # verify that what we're about to sign is a valid signature request
        # from a SSH_MSG_USERAUTH_REQUEST dialogue, and not random data. This
        # is stricter than what OpenSSH's ssh-agent does, but sounds like a
        # good idea nevertheless.
        try:
            SshRequestPublicKeySignature.parse(request.data)
        except ConstructError:
            raise SshAgentProtocolError('Invalid signature in sign request')

        key_digest = (b'SHA256:' + base64.b64encode(hashlib.sha256(
            request.key_blob).digest()).rstrip(b'=')).decode('utf-8')

        try:
            key = self.server.keys[key_digest]
        except KeyError:
            logger.info('Refusing agent sign request, key was not found')
            return SshAgentResponseCode.FAILURE

        if self.is_allowed(key_digest):
            logger.info('Granting agent sign request for user %s', self.user)
            signature = key.sign(request.data, request.flags)
            return (SshAgentResponseCode.SIGN_RESPONSE, signature)
        else:
            logger.info('Refusing agent sign request for user %s', self.user)
            return SshAgentResponseCode.FAILURE

    def handle_lock(self, passphrase):
        """Handle a lock agent command."""
        if not self.is_superuser():
            logger.info('User %s not allowed to lock the agent', self.user)
            return SshAgentResponseCode.FAILURE

        if self.server.lock.lock(passphrase):
            logger.info('Successfully locked the agent')
            return SshAgentResponseCode.SUCCESS
        else:
            logger.info('Failed to lock the agent')
            return SshAgentResponseCode.FAILURE

    def handle_unlock(self, passphrase):
        """Handle an unlock agent command."""
        if not self.is_superuser():
            logger.info('User %s not allowed to unlock the agent', self.user)
            return SshAgentResponseCode.FAILURE

        if self.server.lock.unlock(passphrase):
            logger.info('Successfully unlocked the agent')
            return SshAgentResponseCode.SUCCESS
        else:
            logger.info('Failed to unlock the agent')
            return SshAgentResponseCode.FAILURE

    @staticmethod
    def handle_not_implemented(code):
        """Catch all for not implement commands."""
        logger.debug('Request type %s not implemented', code.name)
        return SshAgentResponseCode.FAILURE


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
        type=pathlib.Path,
        default='/etc/keyholder.d',
        help='directory with SSH keys'
    )
    parser.add_argument(
        '--auth-dir',
        type=pathlib.Path,
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


def mlockall():
    """Locks all of the process' pages into memory.

    This avoids swapping potentially sensitive cryptographic material.
    """
    try:
        libc = ctypes.CDLL('libc.so.6', use_errno=True)
    except OSError:
        # not a Linux system
        return

    flags = MCL_CURRENT | MCL_FUTURE
    if libc.mlockall(flags) == 0:
        logger.debug('Successfully locked memory')
    else:
        error = ctypes.get_errno()
        try:
            error = os.strerror(error)
        except ValueError:
            pass
        logger.debug('Unable to lock memory: %s', error)


def main(argv=sys.argv[1:]):
    """Main entry point; runs forever."""
    args = parse_args(argv)
    setup_logging(args.debug)
    mlockall()

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
