#!/usr/bin/env python3
# link: https://git.p2p.legal/aya/dpgpid/
# desc: generate ed25519 keys for duniter and ipfs from gpg

# Copyleft 2022 Yann Autissier <aya@asycn.io>
# all crypto science belongs to Pascal Engélibert <tuxmain@zettascript.org>
# coming from files available at https://git.p2p.legal/qo-op/Astroport.ONE/tools
# gpgme stuff has been provided by Ben McGinnes
# and comes from http://files.au.adversary.org/crypto/gpgme-python-howto.html
# gpg key extraction is taken from work of Simon Vareille available at
# https://gist.github.com/SimonVareille/fda49baf5f3e15b5c88e25560aeb2822

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import argparse
import base36
import base58
import base64
import configparser
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import duniterpy.key
import gpg
from jwcrypto import jwk
import logging as log
import nacl.bindings
import nacl.encoding
import pgpy
import pynentry
from SecureBytes import clearmem
import os
import re
import struct
import sys
import time
import warnings

__version__='0.0.5'

class keygen:
    def __init__(self):
        self.parser = argparse.ArgumentParser(description="""
        Generate ed25519 keys for duniter and ipfs from gpg.
        It converts a gpg key, a duniter username/password, or any ed25519 key to
        a duniter wallet or an IPFS key.""")
        self.parser.add_argument(
            "-d",
            "--debug",
            action="store_true",
            help="show debug informations (WARNING: including SECRET KEY)",
        )
        self.parser.add_argument(
            "-f",
            "--format",
            choices=['ewif', 'jwk', 'nacl','p2p','pem','pubsec','seed','wif'],
            default=None,
            dest="format",
            help="output file format, default: pem (pkcs8)",
        )
        self.parser.add_argument(
            "-g",
            "--gpg",
            action="store_true",
            help="use gpg key with uid matched by username",
        )
        self.parser.add_argument(
            "-i",
            "--input",
            dest="input",
            help="read ed25519 key from file FILE, autodetect format: {credentials,ewif,jwk,nacl,mnemonic,p2p,pem,pubsec,seed,wif}",
            metavar='FILE',
        )
        self.parser.add_argument(
            "-k",
            "--keys",
            action="store_true",
            help="show public and secret keys",
        )
        self.parser.add_argument(
            "-m",
            "--mnemonic",
            action="store_true",
            help="use username as a DUBP mnemonic passphrase",
        )
        self.parser.add_argument(
            "-o",
            "--output",
            dest="output",
            default=None,
            help="write ed25519 key to file FILE",
            metavar='FILE',
        )
        self.parser.add_argument(
            "-p",
            "--prefix",
            action="store_true",
            help="prefix output text with key type",
        )
        self.parser.add_argument(
            "-q",
            "--quiet",
            action="store_true",
            help="show only errors",
        )
        self.parser.add_argument(
            "-s",
            "--secret",
            action="store_true",
            help="show only secret key",
        )
        self.parser.add_argument(
            "-t",
            "--type",
            choices=['b36mf', 'b58mf', 'b58mh','b64mh','base58','base64','duniter','ipfs','jwk'],
            default="base58",
            dest="type",
            help="output text format, default: base58",
        )
        self.parser.add_argument(
            "-v",
            "--verbose",
            action="store_true",
            help="show more informations",
        )
        self.parser.add_argument(
            "--version",
            action="store_true",
            help="show version and exit",
        )
        self.parser.add_argument(
            'username',
            nargs="?",
        )
        self.parser.add_argument(
            'password',
            nargs="?",
        )

    def _check_args(self, args):
        log.debug("keygen._check_args(%s)" % args)
        if self.input is None and self.username is None:
            self.parser.error('keygen requires an input file or a username')

    def _cleanup(self):
        log.debug("keygen._cleanup()")
        if hasattr(self, 'duniterpy'):
            if hasattr(self.duniterpy, 'seed') and self.duniterpy.seed:
                clearmem(self.duniterpy.seed)
                log.debug("cleared: keygen.duniterpy.seed")
            if hasattr(self.duniterpy, 'sk') and self.duniterpy.sk:
                clearmem(self.duniterpy.sk)
                log.debug("cleared: keygen.duniterpy.sk")
        if hasattr(self, 'ed25519_secret_b36mf') and self.ed25519_secret_b36mf:
            clearmem(self.ed25519_secret_b36mf)
            log.debug("cleared: keygen.ed25519_secret_b36mf")
        if hasattr(self, 'ed25519_secret_b58mf') and self.ed25519_secret_b58mf:
            clearmem(self.ed25519_secret_b58mf)
            log.debug("cleared: keygen.ed25519_secret_b58mf")
        if hasattr(self, 'ed25519_secret_b58mh') and self.ed25519_secret_b58mh:
            clearmem(self.ed25519_secret_b58mh)
            log.debug("cleared: keygen.ed25519_secret_b58mh")
        if hasattr(self, 'ed25519_secret_b64mh') and self.ed25519_secret_b64mh:
            clearmem(self.ed25519_secret_b64mh)
            log.debug("cleared: keygen.ed25519_secret_b64mh")
        if hasattr(self, 'ed25519_secret_base58') and self.ed25519_secret_base58:
            clearmem(self.ed25519_secret_base58)
            log.debug("cleared: keygen.ed25519_secret_base58")
        if hasattr(self, 'ed25519_secret_base64') and self.ed25519_secret_base64:
            clearmem(self.ed25519_secret_base64)
            log.debug("cleared: keygen.ed25519_secret_base64")
        if hasattr(self, 'ed25519_secret_bytes') and self.ed25519_secret_bytes:
            clearmem(self.ed25519_secret_bytes)
            log.debug("cleared: keygen.ed25519_secret_bytes")
        if hasattr(self, 'ed25519_secret_cidv1') and self.ed25519_secret_cidv1:
            clearmem(self.ed25519_secret_cidv1)
            log.debug("cleared: keygen.ed25519_secret_cidv1")
        if hasattr(self, 'ed25519_secret_pem_pkcs8') and self.ed25519_secret_pem_pkcs8:
            clearmem(self.ed25519_secret_pem_pkcs8)
            log.debug("cleared: keygen.ed25515_secret_pem_pkcs8")
        if hasattr(self, 'ed25519_secret_libp2p') and self.ed25519_secret_libp2p:
            clearmem(self.ed25519_secret_libp2p)
            log.debug("cleared: keygen.ed25515_secret_libp2p")
        if hasattr(self, 'ed25519_seed_bytes') and self.ed25519_seed_bytes:
            clearmem(self.ed25519_seed_bytes)
            log.debug("cleared: keygen.ed25519_seed_bytes")
        if hasattr(self, 'ipfs_privkey') and self.ipfs_privkey:
            clearmem(self.ipfs_privkey)
            log.debug("cleared: keygen.ipfs_privkey")
        if hasattr(self, 'jwk'):
            if hasattr(self, 'ed25519_secret_jwk') and self.ed25519_secret_jwk:
                clearmem(self.ed25519_secret_jwk)
                log.debug("cleared: keygen.ed25519_secret_jwk")
            if hasattr(self.jwk, 'd') and self.jwk.d:
                clearmem(self.jwk.d)
                log.debug("cleared: keygen.jwk.d")
        if hasattr(self, 'password') and self.password:
            clearmem(self.password)
            log.debug("cleared: keygen.password")
        if hasattr(self, 'pgp_secret_armor') and self.pgp_secret_armor:
            clearmem(self.pgp_secret_armor)
            log.debug("cleared: keygen.pgp_secret_armor")
        if hasattr(self, 'pgpy'):
            if hasattr(self.pgpy._key.keymaterial, 'p') and self.pgpy._key.keymaterial.p and not isinstance(self.pgpy._key.keymaterial.p, pgpy.packet.fields.ECPoint):
                clearmem(self.pgpy._key.keymaterial.p)
                log.debug("cleared: keygen.pgpy._key.material.p")
            if hasattr(self.pgpy._key.keymaterial, 'q') and self.pgpy._key.keymaterial.q:
                clearmem(self.pgpy._key.keymaterial.q)
                log.debug("cleared: keygen.pgpy._key.material.q")
            if hasattr(self.pgpy._key.keymaterial, 's') and self.pgpy._key.keymaterial.s:
                clearmem(self.pgpy._key.keymaterial.s)
                log.debug("cleared: keygen.pgpy._key.material.s")
        if hasattr(self, 'username') and self.username:
            clearmem(self.username)
            log.debug("cleared: keygen.username")

    def _cli(self, argv):
        args = self.parser.parse_args(argv)
        vars(self).update(vars(args))

        # display version
        if args.version:
            version()
            sys.exit()

        # define log format
        log_format='%(asctime)s %(levelname)s: %(message)s'
        log_datefmt='%Y/%m/%d %H:%M:%S'
        if args.debug:
            log_level='DEBUG'
        elif args.quiet:
            log_level='ERROR'
        elif args.verbose:
            log_level='INFO'
        else:
            log_level='WARNING'
        log.basicConfig(format=log_format, datefmt=log_datefmt, level=log_level)
        log.debug("keygen.run(%s)" % argv)

        self._check_args(args)
        self._load_config()
        self.gpg = gpg.Context(armor=True, offline=True)
        self.gpg.set_passphrase_cb(self.gpg_passphrase_cb)
        self.ed25519_from(args)
        method = getattr(self, f'do_{self.type}', self._invalid_type)
        return method()

    def _invalid_type(self):
        log.debug("keygen._invalid_type()")
        self.parser.error(f"type {self.type} is not valid.")

    def _load_config(self):
        log.debug("keygen._load_config()")
        self.config = configparser.RawConfigParser()
        config_dir = os.path.join(os.environ.get('XDG_CONFIG_HOME', os.path.expanduser('~/.config')), 'dpgpid')
        log.debug("config_dir=%s" % config_dir)
        self.config.read( [config_dir + '/keygen.conf'] )

    def _output(self, public_key, secret_key, public_key_prefix, secret_key_prefix):
        log.debug("keygen._output()")
        if self.output is None:
            self._output_text(public_key, secret_key, public_key_prefix, secret_key_prefix)
        else:
            self._output_file()
            os.chmod(self.output, 0o600)
        self._cleanup()

    def _output_file(self):
        log.debug("keygen._output_file()")
        try:
            if self.format == 'dewif':
                if not hasattr(self, 'duniterpy'):
                    self.duniterpy_from_ed25519_seed_bytes()
                if not self.password:
                    with pynentry.PynEntry() as p:
                        p.description = f"""Data in DEWIF file needs to be encrypted.
                        Please enter a password to encrypt seed.
                        """
                        p.prompt = 'Passphrase:'
                        try:
                            self.password = p.get_pin()
                        except pynentry.PinEntryCancelled:
                            log.warning('Cancelled! Goodbye.')
                            self._cleanup()
                            exit(1)
                self.duniterpy.save_dewif_v1_file(self.output, self.password)
            elif self.format == 'ewif':
                if not hasattr(self, 'duniterpy'):
                    self.duniterpy_from_ed25519_seed_bytes()
                if not self.password:
                    with pynentry.PynEntry() as p:
                        p.description = f"""Data in EWIF file needs to be encrypted.
                        Please enter a password to encrypt seed.
                        """
                        p.prompt = 'Passphrase:'
                        try:
                            self.password = p.get_pin()
                        except pynentry.PinEntryCancelled:
                            log.warning('Cancelled! Goodbye.')
                            self._cleanup()
                            exit(1)
                self.duniterpy.save_ewif_file(self.output, self.password)
            elif self.format == 'jwk':
                if not hasattr(self, 'jwk'):
                    self.jwk_from_ed25519()
                with open(self.output, "w") as file:
                    file.write(self.jwk.export())
            elif self.format == 'nacl':
                if not hasattr(self, 'duniterpy'):
                    self.duniterpy_from_ed25519_seed_bytes()
                self.duniterpy.save_private_key(self.output)
            elif self.format == 'p2p':
                if not hasattr(self, 'ed25519_secret_libp2p'):
                    self.libp2p_from_ed25519()
                with open(self.output, "wb") as file:
                    file.write(self.ed25519_secret_libp2p)
            elif self.format == 'pubsec':
                if not hasattr(self, 'duniterpy'):
                    self.duniterpy_from_ed25519_seed_bytes()
                self.duniterpy.save_pubsec_file(self.output)
            elif self.format == 'seed':
                if not hasattr(self, 'duniterpy'):
                    self.duniterpy_from_ed25519_seed_bytes()
                self.duniterpy.save_seedhex_file(self.output)
            elif self.format == 'wif':
                if not hasattr(self, 'duniterpy'):
                    self.duniterpy_from_ed25519_seed_bytes()
                self.duniterpy.save_wif_file(self.output)
            else:
                if not hasattr(self, 'ed25519_secret_pem_pkcs8'):
                    self.pem_pkcs8_from_ed25519()
                with open(self.output, "w") as file:
                    file.write(self.ed25519_secret_pem_pkcs8)
        except Exception as e:
            log.error(f'Unable to output file {self.output}: {e}')
            self._cleanup()
            exit(2)

    def _output_text(self, public_key, secret_key, public_key_prefix, secret_key_prefix):
        log.debug("keygen._output_text()")
        if self.keys or not self.secret:
            print("%s" % ''.join([self.prefix * public_key_prefix, public_key]))
        if self.keys or self.secret:
            print("%s" % ''.join([self.prefix * secret_key_prefix, secret_key]))

    def b36mf_from_cidv1(self):
        log.debug("keygen.b36mf_from_cidv1()")
        if not hasattr(self, 'ed25519_public_cidv1') or not hasattr(self, 'ed25519_secret_cidv1'):
            self.cidv1_from_libp2p()
        try:
            self.ed25519_public_b36mf = 'k' + base36.dumps(int.from_bytes(self.ed25519_public_cidv1, byteorder='big'))
            self.ed25519_secret_b36mf = 'k' + base36.dumps(int.from_bytes(self.ed25519_secret_cidv1, byteorder='big'))
        except Exception as e:
            log.error(f'Unable to get b36mf from cidv1: {e}')
            self._cleanup()
            exit(2)
        log.debug("keygen.ed25519_public_b36mf=%s" % self.ed25519_public_b36mf)
        log.debug("keygen.ed25519_secret_b36mf=%s" % self.ed25519_secret_b36mf)

    def b58mf_from_cidv1(self):
        log.debug("keygen.b58mf_from_cidv1()")
        if not hasattr(self, 'ed25519_public_cidv1') or not hasattr(self, 'ed25519_secret_cidv1'):
            self.cidv1_from_libp2p()
        try:
            self.ed25519_public_b58mf = 'z' + base58.b58encode(self.ed25519_public_cidv1).decode('ascii')
            self.ed25519_secret_b58mf = 'z' + base58.b58encode(self.ed25519_secret_cidv1).decode('ascii')
        except Exception as e:
            log.error(f'Unable to get b58mf from cidv1: {e}')
            self._cleanup()
            exit(2)
        log.debug("keygen.ed25519_public_b58mf=%s" % self.ed25519_public_b58mf)
        log.debug("keygen.ed25519_secret_b58mf=%s" % self.ed25519_secret_b58mf)

    def b58mh_from_libp2p(self):
        log.debug("keygen.b58mh_from_libp2p()")
        if not hasattr(self, 'ed25519_public_libp2p') or not hasattr(self, 'ed25519_secret_libp2p'):
            self.libp2p_from_ed25519()
        try:
            self.ed25519_public_b58mh = base58.b58encode(self.ed25519_public_libp2p).decode('ascii')
            self.ed25519_secret_b58mh = base58.b58encode(self.ed25519_secret_libp2p).decode('ascii')
        except Exception as e:
            log.error(f'Unable to get b58mh from libp2p: {e}')
            self._cleanup()
            exit(2)
        log.debug("keygen.ed25519_public_b58mh=%s" % self.ed25519_public_b58mh)
        log.debug("keygen.ed25519_secret_b58mh=%s" % self.ed25519_secret_b58mh)

    def b64mh_from_libp2p(self):
        log.debug("keygen.b64mh_from_libp2p()")
        if not hasattr(self, 'ed25519_public_libp2p') or not hasattr(self, 'ed25519_secret_libp2p'):
            self.libp2p_from_ed25519()
        try:
            self.ed25519_public_b64mh = base64.b64encode(self.ed25519_public_libp2p).decode('ascii')
            self.ed25519_secret_b64mh = base64.b64encode(self.ed25519_secret_libp2p).decode('ascii')
        except Exception as e:
            log.error(f'Unable to get b64mh from libp2p: {e}')
            self._cleanup()
            exit(2)
        log.debug("keygen.ed25519_public_b64mh=%s" % self.ed25519_public_b64mh)
        log.debug("keygen.ed25519_secret_b64mh=%s" % self.ed25519_secret_b64mh)

    def base58_from_ed25519(self):
        log.debug("keygen.base58_from_ed25519()")
        try:
            self.ed25519_public_base58 = base58.b58encode(self.ed25519_public_bytes).decode('ascii')
            self.ed25519_secret_base58 = base58.b58encode(self.ed25519_secret_bytes).decode('ascii')
        except Exception as e:
            log.error(f'Unable to get base58 from ed25519: {e}')
            self._cleanup()
            exit(2)
        log.debug("keygen.ed25519_public_base58=%s" % self.ed25519_public_base58)
        log.debug("keygen.ed25519_secret_base58=%s" % self.ed25519_secret_base58)

    def base64_from_ed25519(self):
        log.debug("keygen.base64_from_ed25519()")
        try:
            self.ed25519_public_base64 = base64.b64encode(self.ed25519_public_bytes).decode('ascii')
            self.ed25519_secret_base64 = base64.b64encode(self.ed25519_secret_bytes).decode('ascii')
        except Exception as e:
            log.error(f'Unable to get base64 from ed25519: {e}')
            self._cleanup()
            exit(2)
        log.debug("keygen.ed25519_public_base64=%s" % self.ed25519_public_base64)
        log.debug("keygen.ed25519_secret_base64=%s" % self.ed25519_secret_base64)

    def cidv1_from_libp2p(self):
        log.debug("keygen.cidv1_from_libp2p()")
        if not hasattr(self, 'ed25519_public_libp2p') or not hasattr(self, 'ed25519_secret_libp2p'):
            self.libp2p_from_ed25519()
        try:
            # \x01: multicodec cid prefix = CIDv1
            # \x72: multicodec content prefix = libp2p-key
            self.ed25519_public_cidv1 = b'\x01\x72' + self.ed25519_public_libp2p
            self.ed25519_secret_cidv1 = b'\x01\x72' + self.ed25519_secret_libp2p
        except Exception as e:
            log.error(f'Unable to get cidv1 from libp2p: {e}')
            self._cleanup()
            exit(2)
        log.debug("keygen.ed25519_public_cidv1=%s" % self.ed25519_public_cidv1)
        log.debug("keygen.ed25519_secret_cidv1=%s" % self.ed25519_secret_cidv1)

    def do_b36mf(self):
        log.debug("keygen.do_b36mf()")
        self.libp2p_from_ed25519()
        self.cidv1_from_libp2p()
        self.b36mf_from_cidv1()
        self._output(self.ed25519_public_b36mf, self.ed25519_secret_b36mf, 'pub: ', 'sec: ')

    def do_b58mf(self):
        log.debug("keygen.do_b58mf()")
        self.libp2p_from_ed25519()
        self.cidv1_from_libp2p()
        self.b58mf_from_cidv1()
        self._output(self.ed25519_public_b58mf, self.ed25519_secret_b58mf, 'pub: ', 'sec: ')

    def do_b58mh(self):
        log.debug("keygen.do_b58mh()")
        self.libp2p_from_ed25519()
        self.b58mh_from_libp2p()
        self._output(self.ed25519_public_b58mh, self.ed25519_secret_b58mh, 'pub: ', 'sec: ')

    def do_b64mh(self):
        log.debug("keygen.do_b64mh()")
        self.libp2p_from_ed25519()
        self.b64mh_from_libp2p()
        self._output(self.ed25519_public_b64mh, self.ed25519_secret_b64mh, 'pub: ', 'sec: ')

    def do_base58(self):
        log.debug("keygen.do_base58()")
        self.base58_from_ed25519()
        self._output(self.ed25519_public_base58, self.ed25519_secret_base58, 'pub: ', 'sec: ')

    def do_base64(self):
        log.debug("keygen.do_base64()")
        self.base64_from_ed25519()
        self._output(self.ed25519_public_base64, self.ed25519_secret_base64, 'pub: ', 'sec: ')

    def do_duniter(self):
        log.debug("keygen.do_duniter()")
        if not self.format:
            self.format = 'pubsec'
        self.base58_from_ed25519()
        self._output(self.ed25519_public_base58, self.ed25519_secret_base58, 'pub: ', 'sec: ')

    def do_ipfs(self):
        log.debug("keygen.do_ipfs()")
        self.libp2p_from_ed25519()
        self.b58mh_from_libp2p()
        self.b64mh_from_libp2p()
        self._output(self.ed25519_public_b58mh, self.ed25519_secret_b64mh, 'PeerID: ', 'PrivKEY: ')

    def do_jwk(self):
        log.debug("keygen.do_jwk()")
        self.jwk_from_ed25519()
        self._output(self.ed25519_public_jwk, self.ed25519_secret_jwk, 'pub: ', 'sec: ')

    def duniterpy_from_credentials(self):
        log.debug("keygen.duniterpy_from_credentials()")
        try:
            scrypt_params = duniterpy.key.scrypt_params.ScryptParams(
                int(self.config.get('scrypt', 'n')) if self.config.has_option('scrypt', 'n') else 4096,
                int(self.config.get('scrypt', 'r')) if self.config.has_option('scrypt', 'r') else 16,
                int(self.config.get('scrypt', 'p')) if self.config.has_option('scrypt', 'p') else 1,
                int(self.config.get('scrypt', 'sl')) if self.config.has_option('scrypt', 'sl') else 32,
            )
            if not self.password:
                with pynentry.PynEntry() as p:
                    p.description = f"""Please enter the passord for username "{self.username}"."""
                    p.prompt = 'Passsord:'
                    try:
                        self.password = p.get_pin()
                    except pynentry.PinEntryCancelled:
                        log.warning('Cancelled! Goodbye.')
                        self._cleanup()
                        exit(1)
            self.duniterpy = duniterpy.key.SigningKey.from_credentials(
                self.username,
                self.password,
                scrypt_params
            )
        except Exception as e:
            log.error(f'Unable to get duniter from credentials: {e}')
            self._cleanup()
            exit(2)
        log.debug("keygen.duniterpy.seed: %s" % self.duniterpy.seed)

    def duniterpy_from_ed25519_seed_bytes(self):
        log.debug("keygen.duniterpy_from_ed25519_seed_bytes()")
        try:
            self.duniterpy = duniterpy.key.SigningKey(self.ed25519_seed_bytes)
        except Exception as e:
            log.error(f'Unable to get duniterpy from ed25519 seed bytes: {e}')
            self._cleanup()
            exit(2)
        log.debug("keygen.duniterpy.seed: %s" % self.duniterpy.seed)

    def duniterpy_from_file(self):
        log.debug("keygen.duniterpy_from_file()")
        try:
            with open(self.input, 'r') as file:
                lines = file.readlines()
                if len(lines) > 0:
                    line = lines[0].strip()
                    regex_ewif = re.compile('^Type: EWIF$')
                    regex_jwk = re.compile('^\\s*{\\s*"crv":\\s*"Ed25519",\\s*"d":\\s*"(.)+",\\s*"kty":\\s*"OKP",\\s*"x":\\s*"(.)+"\\s*}')
                    regex_nacl = re.compile('^\\s*{\\s*"priv":\\s*"[0-9a-fA-F]+",\\s*"verify":\\s*"[0-9a-fA-F]+",\\s*"sign":\\s*"[0-9a-fA-F]+"\\s*}')
                    regex_pem = re.compile('^-----BEGIN PRIVATE KEY-----$')
                    regex_pubsec = re.compile('^Type: PubSec$')
                    regex_seed = re.compile('^[0-9a-fA-F]{64}$')
                    regex_ssb = re.compile('\\s*{\\s*"curve":\\s*"ed25519",\\s*"public":\\s*"(.+)\\.ed25519",\\s*"private":\\s*"(.+)\\.ed25519",\\s*"id":\\s*"@(.+).ed25519"\\s*}')
                    regex_wif = re.compile('^Type: WIF$')
                    if re.search(regex_ewif, line):
                        log.info("input file format detected: ewif")
                        if not self.password:
                            with pynentry.PynEntry() as p:
                                p.description = f"""Data in EWIF file is encrypted.
                                Please enter a password to decrypt seed.
                                """
                                p.prompt = 'Passphrase:'
                                try:
                                    self.password = p.get_pin()
                                except pynentry.PinEntryCancelled:
                                    log.warning('Cancelled! Goodbye.')
                                    self._cleanup()
                                    exit(1)
                        self.duniterpy = duniterpy.key.SigningKey.from_ewif_file(self.input, self.password)
                    elif re.search(regex_jwk, line):
                        log.info("input file format detected: jwk")
                        self.jwk_from_json(line)
                        self.ed25519_seed_bytes_from_jwk()
                        self.duniterpy_from_ed25519_seed_bytes()
                    elif re.search(regex_nacl, line):
                        log.info("input file format detected: nacl")
                        self.duniterpy = duniterpy.key.SigningKey.from_private_key(self.input)
                    elif re.search(regex_pem, line):
                        log.info("input file format detected: pem")
                        self.ed25519_seed_bytes_from_pem(''.join(lines).encode())
                        self.duniterpy_from_ed25519_seed_bytes()
                    elif re.search(regex_pubsec, line):
                        log.info("input file format detected: pubsec")
                        self.duniterpy = duniterpy.key.SigningKey.from_pubsec_file(self.input)
                    elif re.search(regex_seed, line):
                        log.info("input file format detected: seed")
                        self.duniterpy = duniterpy.key.SigningKey.from_seedhex_file(self.input)
                    elif re.search(regex_ssb, line):
                        log.info("input file format detected: ssb")
                        self.duniterpy = duniterpy.key.SigningKey.from_ssb_file(self.input)
                    elif re.search(regex_wif, line):
                        log.info("input file format detected: wif")
                        self.duniterpy = duniterpy.key.SigningKey.from_wif_file(self.input)
                    elif len(line.split(' ')) == 12:
                        log.info("input file format detected: mnemonic")
                        self.username = line
                        self.duniterpy_from_mnemonic()
                    elif len(lines) > 1:
                        log.info("input file format detected: credentials")
                        self.username = line
                        self.password = lines[1].strip()
                        self.duniterpy_from_credentials()
                    else:
                        raise NotImplementedError('unknown input file format.')
                else:
                    raise NotImplementedError('empty file.')
        except UnicodeDecodeError as e:
            try:
                with open(self.input, 'rb') as file:
                    lines = file.readlines()
                    if len(lines) > 0:
                        line = lines[0].strip()
                        regex_dewif = re.compile(b'^\x00\x00\x00\x01\x00\x00\x00\x01')
                        regex_p2p = re.compile(b'^\x08\x01\x12@')
                        if re.search(regex_dewif, line):
                            log.info("input file format detected: dewif")
                            if not self.password:
                                with pynentry.PynEntry() as p:
                                    p.description = f"""Data in DEWIF file is encrypted.
                                    Please enter a password to decrypt seed.
                                    """
                                    p.prompt = 'Passphrase:'
                                    try:
                                        self.password = p.get_pin()
                                    except pynentry.PinEntryCancelled:
                                        log.warning('Cancelled! Goodbye.')
                                        self._cleanup()
                                        exit(1)
                            self.duniterpy = duniterpy.key.SigningKey.from_dewif_file(self.input, self.password)
                        if re.search(regex_p2p, line):
                            log.info("input file format detected: p2p")
                            self.ed25519_secret_libp2p = line
                            self.ed25519_seed_bytes_from_libp2p()
                            self.duniterpy_from_ed25519_seed_bytes()
                        else:
                            raise NotImplementedError('unknown input file format.')
                    else:
                        raise NotImplementedError('empty file.')
            except Exception as e:
                log.error(f'Unable to get duniterpy from file {self.input}: {e}')
                self._cleanup()
                exit(2)
        except Exception as e:
            log.error(f'Unable to get duniterpy from file {self.input}: {e}')
            self._cleanup()
            exit(2)
        log.debug("keygen.duniterpy.seed: %s" % self.duniterpy.seed)

    def duniterpy_from_mnemonic(self):
        log.debug("keygen.duniterpy_from_mnemonic()")
        try:
            scrypt_params = duniterpy.key.scrypt_params.ScryptParams(
                int(self.config.get('scrypt', 'n')) if self.config.has_option('scrypt', 'n') else 4096,
                int(self.config.get('scrypt', 'r')) if self.config.has_option('scrypt', 'r') else 16,
                int(self.config.get('scrypt', 'p')) if self.config.has_option('scrypt', 'p') else 1,
                int(self.config.get('scrypt', 'sl')) if self.config.has_option('scrypt', 'sl') else 32,
            )
            self.duniterpy = duniterpy.key.SigningKey.from_dubp_mnemonic(
                self.username,
                scrypt_params
            )
        except Exception as e:
            log.error(f'Unable to get duniterpy from mnemonic: {e}')
            self._cleanup()
            exit(2)
        log.debug("keygen.duniterpy.seed: %s" % self.duniterpy.seed)

    def ed25519_from(self, args):
        log.debug("keygen.ed25519_from(%s)" % args)
        if args.gpg:
            self.ed25519_from_gpg()
        else:
            if self.input:
                self.duniterpy_from_file()
            else:
                if self.mnemonic:
                    self.duniterpy_from_mnemonic()
                else:
                    self.duniterpy_from_credentials()
            self.ed25519_from_duniterpy()

    def ed25519_from_duniterpy(self):
        log.debug("keygen.ed25519_from_duniterpy()")
        try:
            self.ed25519_seed_bytes_from_duniterpy()
            self.ed25519_from_seed_bytes()
        except:
            log.error(f'Unable to get ed25519 from duniterpy: {e}')
            self._cleanup()
            exit(2)

    def ed25519_from_gpg(self):
        log.debug("keygen.ed25519_from_gpg()")
        try:
            self.pgpy_from_gpg()
            self.ed25519_from_pgpy()
        except Exception as e:
            log.error(f'Unable to get ed25519 from pgp: {e}')
            self._cleanup()
            exit(2)

    def ed25519_from_pgpy(self):
        log.debug("keygen.ed25519_from_pgpy()")
        try:
            log.debug("keygen.pgpy.fingerprint.keyid=%s" % self.pgpy.fingerprint.keyid)
            log.debug("keygen.pgpy.is_protected=%s" % self.pgpy.is_protected)
            if self.pgpy.is_protected:
                if not self.password:
                    with pynentry.PynEntry() as p:
                        p.description = f"""The exported pgp key id "{self.pgpy.fingerprint.keyid}" of user "{self.username}" is password protected.
                        Please enter the passphrase again to unlock it.
                        """
                        p.prompt = 'Passphrase:'
                        try:
                            self.password = p.get_pin()
                        except pynentry.PinEntryCancelled:
                            log.warning('Cancelled! Goodbye.')
                            self._cleanup()
                            exit(1)
                try:
                    with warnings.catch_warnings():
                        # remove CryptographyDeprecationWarning about deprecated
                        # SymmetricKeyAlgorithm IDEA, CAST5 and Blowfish (PGPy v0.5.4)
                        warnings.simplefilter('ignore')
                        with self.pgpy.unlock(self.password):
                            assert self.pgpy.is_unlocked
                            log.debug("keygen.pgpy.is_unlocked=%s" % self.pgpy.is_unlocked)
                            self.ed25519_seed_bytes_from_pgpy()
                except Exception as e:
                    log.error(f"""Unable to unlock pgp secret key id "{self.pgpy.fingerprint.keyid}" of user "{self.username}": {e}""")
                    self._cleanup()
                    exit(2)
            else:
                self.ed25519_seed_bytes_from_pgpy()
            self.ed25519_from_seed_bytes()
        except Exception as e:
            log.error(f'Unable to get ed25519 seed bytes from pgpy: {e}')
            self._cleanup()
            exit(2)

    def ed25519_from_seed_bytes(self):
        log.debug("keygen.ed25519_from_seed_bytes()")
        try:
            self.ed25519_public_bytes, self.ed25519_secret_bytes = nacl.bindings.crypto_sign_seed_keypair(self.ed25519_seed_bytes)
            self.ed25519 = ed25519.Ed25519PrivateKey.from_private_bytes(self.ed25519_seed_bytes)
        except Exception as e:
            log.error(f'Unable to get ed25519 from seed bytes: {e}')
            self._cleanup()
            exit(2)
        log.debug("keygen.ed25519_public_bytes=%s" % self.ed25519_public_bytes)
        log.debug("keygen.ed25519_secret_bytes=%s" % self.ed25519_secret_bytes)

    def ed25519_seed_bytes_from_duniterpy(self):
        log.debug("keygen.ed25519_seed_bytes_from_duniterpy()")
        try:
            self.ed25519_seed_bytes = self.duniterpy.sk[:32]
        except Exception as e:
            log.error(f'Unable to get ed25519 seed bytes from duniterpy: {e}')
            self._cleanup()
            exit(2)
        log.debug("keygen.ed25519_seed_bytes=%s" % self.ed25519_seed_bytes)

    def ed25519_seed_bytes_from_jwk(self):
        log.debug("keygen.ed25519_seed_bytes_from_jwk()")
        try:
            self.ed25519_seed_bytes = self.jwk._okp_pri().private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
        except Exception as e:
            log.error(f'Unable to get ed25519 seed bytes from jwk: {e}')
            self._cleanup()
            exit(2)

    def ed25519_seed_bytes_from_pem(self, pem):
        log.debug("keygen.ed25519_seed_bytes_from_pem()")
        try:
            self.ed25519_seed_bytes = serialization.load_pem_private_key(pem, password=None).private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
        except Exception as e:
            log.error(f'Unable to get ed25519 seed bytes from pem: {e}')
            self._cleanup()
            exit(2)

    def ed25519_seed_bytes_from_pgpy(self):
        log.debug("keygen.ed25519_seed_bytes_from_pgpy()")
        try:
            self.pgpy_key_type()
            if self.pgpy_key_type == 'RSA':
                log.debug("keygen.pgpy._key.keymaterial.p=%s" % self.pgpy._key.keymaterial.p)
                log.debug("keygen.pgpy._key.keymaterial.q=%s" % self.pgpy._key.keymaterial.q)
                # rsa custom seed: sha256 hash of (p + q), where + is a string concatenation
                rsa_int = int(str(self.pgpy._key.keymaterial.p) + str(self.pgpy._key.keymaterial.q))
                rsa_len = (rsa_int.bit_length() + 7) // 8
                self.ed25519_seed_bytes = nacl.bindings.crypto_hash_sha256((rsa_int).to_bytes(rsa_len,byteorder='big'))
            elif self.pgpy_key_type in ('ECDSA', 'EdDSA', 'ECDH'):
                log.debug("keygen.pgpy._key.keymaterial.s=%s" % self.pgpy._key.keymaterial.s)
                self.ed25519_seed_bytes = self.pgpy._key.keymaterial.s.to_bytes(32, byteorder='big')
            else:
                raise NotImplementedError(f"getting seed from pgp key type {self.pgpy_key_type} is not implemented")
        except Exception as e:
            log.error(f'Unable to get ed25519 seed bytes from pgpy: {e}')
            self._cleanup()
            exit(2)
        log.debug("keygen.ed25519_seed_bytes=%s" % self.ed25519_seed_bytes)

    def ed25519_seed_bytes_from_libp2p(self):
        log.debug("keygen.ed25519_seed_bytes_from_libp2p()")
        try:
            self.ed25519_seed_bytes = self.ed25519_secret_libp2p.lstrip(b'\x08\x01\x12@')[:32]
        except Exception as e:
            log.error(f'Unable to get ed25519 seed bytes from libp2p: {e}')
            self._cleanup()
            exit(2)
        log.debug("keygen.ed25519_seed_bytes=%s" % self.ed25519_seed_bytes)

    def gpg_passphrase_cb(self, uid_hint, passphrase_info, prev_was_bad):
        log.debug("keygen.gpg_passphrase_cb(%s, %s, %s)" % (uid_hint, passphrase_info, prev_was_bad))
        return self.password

    def jwk_from_ed25519(self):
        log.debug("keygen.jwk_from_ed25519()")
        try:
            self.jwk = jwk.JWK.from_pyca(self.ed25519)
            self.ed25519_public_jwk = self.jwk.export_public()
            self.ed25519_secret_jwk = self.jwk.export_private()
        except Exception as e:
            log.error(f'Unable to get jwk from ed25519: {e}')
            self._cleanup()
            exit(2)

    def jwk_from_json(self, json):
        log.debug("keygen.jwk_from_json()")
        try:
            self.jwk = jwk.JWK.from_json(json)
        except Exception as e:
            log.error(f'Unable to get jwk from json: {e}')
            self._cleanup()
            exit(2)

    def pem_pkcs8_from_ed25519(self):
        log.debug("keygen.pem_pkcs8_from_ed25519()")
        try:
            self.ed25519_secret_pem_pkcs8 = self.ed25519.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()).decode('ascii')
        except Exception as e:
            log.error(f'Unable to get pem pkcs8 from ed25519: {e}')
            self._cleanup()
            exit(2)
        log.debug("keygen.ed25519_secret_pem_pkcs8=%s" % self.ed25519_secret_pem_pkcs8)

    def pgpy_from_gpg(self):
        log.debug("keygen.pgpy_from_gpg()")
        try:
            self.gpg_secret_keys = list(self.gpg.keylist(pattern=self.username, secret=True))
            log.debug("keygen.gpg_secret_keys=%s" % self.gpg_secret_keys)
            if not self.gpg_secret_keys:
                log.warning(f"""Unable to find any key matching "{self.username}".""")
                self._cleanup()
                exit(1)
            else:
                self.gpg_secret_key = self.gpg_secret_keys[0]
                log.info(f"""Found key id "{self.gpg_secret_key.fpr}" matching "{self.username}".""")
            log.debug("keygen.gpg_secret_key.expired=%s" % self.gpg_secret_key.expired)
            log.debug("keygen.gpg_secret_key.fpr=%s" % self.gpg_secret_key.fpr)
            log.debug("keygen.gpg_secret_key.revoked=%s" % self.gpg_secret_key.revoked)
            log.debug("keygen.gpg_secret_key.uids=%s" % self.gpg_secret_key.uids)
            log.debug("keygen.gpg_secret_key.owner_trust=%s" % self.gpg_secret_key.owner_trust)
            log.debug("keygen.gpg_secret_key.last_update=%s" % self.gpg_secret_key.last_update)
            if self.password:
                self.gpg.set_pinentry_mode(gpg.constants.PINENTRY_MODE_LOOPBACK)
            self.pgp_public_armor = self.gpg.key_export(self.gpg_secret_key.fpr)
            self.pgp_secret_armor = self.gpg.key_export_secret(self.gpg_secret_key.fpr)
            log.debug("keygen.pgp_secret_armor=%s" % self.pgp_secret_armor)
            if not self.pgp_secret_armor:
                log.error(f"""Unable to export gpg secret key id "{self.gpg_secret_key.fpr}" of user "{self.username}". Please check your password!""")
                self._cleanup()
                exit(2)
            with warnings.catch_warnings():
                # remove CryptographyDeprecationWarning about deprecated
                # SymmetricKeyAlgorithm IDEA, CAST5 and Blowfish (PGPy v0.5.4)
                warnings.simplefilter('ignore')
                self.pgpy, _ = pgpy.PGPKey.from_blob(self.pgp_secret_armor)
        except Exception as e:
            log.error(f'Unable to get pgpy from gpg: {e}')
            self._cleanup()
            exit(2)

    def pgpy_key_type(self):
        log.debug("keygen.pgpy_key_type()")
        if isinstance(self.pgpy._key.keymaterial, pgpy.packet.fields.RSAPriv):
            self.pgpy_key_type = 'RSA'
        elif isinstance(self.pgpy._key.keymaterial, pgpy.packet.fields.DSAPriv):
            self.pgpy_key_type = 'DSA'
        elif isinstance(self.pgpy._key.keymaterial, pgpy.packet.fields.ElGPriv):
            self.pgpy_key_type = 'ElGamal'
        elif isinstance(self.pgpy._key.keymaterial, pgpy.packet.fields.ECDSAPriv):
            self.pgpy_key_type = 'ECDSA'
        elif isinstance(self.pgpy._key.keymaterial, pgpy.packet.fields.EdDSAPriv):
            self.pgpy_key_type = 'EdDSA'
        elif isinstance(self.pgpy._key.keymaterial, pgpy.packet.fields.ECDHPriv):
            self.pgpy_key_type = 'ECDH'
        else:
            self.pgpy_key_type = 'undefined'
        log.debug("keygen.pgpy_key_type=%s" % self.pgpy_key_type)

    def libp2p_from_ed25519(self):
        # libp2p protobuf version 2
        log.debug("keygen.libp2p_from_ed25519()")
        try:
            # \x00: multihash prefix = id
            # \x24: multihash length = 36 bytes
            self.ed25519_public_libp2p = b'\x00$\x08\x01\x12 ' + self.ed25519_public_bytes
            self.ed25519_secret_libp2p = b'\x08\x01\x12@' + self.ed25519_secret_bytes

        except Exception as e:
            log.error(f'Unable to get libp2p from ed25519: {e}')
            self._cleanup()
            exit(2)
        log.debug("keygen.ed25519_public_libp2p=%s" % self.ed25519_public_libp2p)
        log.debug("keygen.ed25519_secret_libp2p=%s" % self.ed25519_secret_libp2p)

def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    return keygen()._cli(argv)

def version(version=__version__):
    print("%s v%s" % (sys.argv[0],version))

if __name__ == "__main__":
    sys.exit(main())
