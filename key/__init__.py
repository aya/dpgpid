#!/usr/bin/env python3
# link: https://git.p2p.legal/aya/dpgpid/
# desc: dpgpid builds a decentralized gpg world of trust with did over ipfs

# Copyleft 2022 Yann Autissier <aya@asycn.io>

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

from cryptography.hazmat.primitives import serialization
from jwcrypto.jwk import JWK
from SecureBytes import clearmem
import base36
import base58
import base64
import duniterpy.key
import gpg
import logging as log
import pgpy
import pynentry
import re
import warnings

def from_args(args, config):
    log.debug("key.from_args(%s, %s)" % (args, config))
    from key import ed25519
    if args.gpg:
        _gpg = gpg.Context(armor=True, offline=True)
        return from_gpg(_gpg, args.username[0], args.password)
    else:
        scrypt_params = duniterpy.key.scrypt_params.ScryptParams(
            int(config.get('scrypt', 'n')) if config and config.has_option('scrypt', 'n') else 4096,
            int(config.get('scrypt', 'r')) if config and config.has_option('scrypt', 'r') else 16,
            int(config.get('scrypt', 'p')) if config and config.has_option('scrypt', 'p') else 1,
            int(config.get('scrypt', 'sl')) if config and config.has_option('scrypt', 'sl') else 32,
        )
        if args.input:
            return from_file(args.input, args.password, scrypt_params)
        else:
            if args.mnemonic:
                return from_mnemonic(' '.join(args.username), scrypt_params)
            else:
                return from_credentials(args.username[0], args.password, scrypt_params)

def from_credentials(username, password=None, scrypt_params=None):
    log.debug("key.from_credentials(%s, %s, %s)" % (username, password, scrypt_params))
    try:
        if not password:
            with pynentry.PynEntry() as p:
                p.description = f"""Please enter the passord for username "{username}"."""
                p.prompt = 'Passsord:'
                try:
                    password = p.get_pin()
                except pynentry.PinEntryCancelled:
                    log.warning('Cancelled! Goodbye.')
                    exit(1)
        return from_duniterpy(duniterpy.key.SigningKey.from_credentials(
            username,
            password,
            scrypt_params
        ))
    except Exception as e:
        log.error(f'Unable to get key from credentials: {e}')
        exit(2)

def from_duniterpy(duniterpy):
    log.debug("key.from_duniterpy(%s)" % duniterpy)
    key = ed25519.from_duniterpy(duniterpy)
    key.duniterpy = duniterpy
    return key

def from_file(input_file, password=None, scrypt_params=None):
    log.debug("key.from_file(%s, %s, %s)" % (input_file, password, scrypt_params))
    try:
        with open(input_file, 'r') as file:
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
                    if not password:
                        with pynentry.PynEntry() as p:
                            p.description = f"""Data in EWIF file is encrypted.
                            Please enter a password to decrypt seed.
                            """
                            p.prompt = 'Passphrase:'
                            try:
                                password = p.get_pin()
                            except pynentry.PinEntryCancelled:
                                log.warning('Cancelled! Goodbye.')
                                exit(1)
                    return from_duniterpy(duniterpy.key.SigningKey.from_ewif_file(input_file, password))
                elif re.search(regex_jwk, line):
                    log.info("input file format detected: jwk")
                    return from_jwk(JWK.from_json(line))
                elif re.search(regex_nacl, line):
                    log.info("input file format detected: nacl")
                    return from_duniterpy(duniterpy.key.SigningKey.from_private_key(input_file))
                elif re.search(regex_pem, line):
                    log.info("input file format detected: pem")
                    return from_pem(''.join(lines).encode())
                elif re.search(regex_pubsec, line):
                    log.info("input file format detected: pubsec")
                    return from_duniterpy(duniterpy.key.SigningKey.from_pubsec_file(input_file))
                elif re.search(regex_seed, line):
                    log.info("input file format detected: seed")
                    return from_duniterpy(duniterpy.key.SigningKey.from_seedhex_file(input_file))
                elif re.search(regex_ssb, line):
                    log.info("input file format detected: ssb")
                    return from_duniterpy(duniterpy.key.SigningKey.from_ssb_file(input_file))
                elif re.search(regex_wif, line):
                    log.info("input file format detected: wif")
                    return from_duniterpy(duniterpy.key.SigningKey.from_wif_file(input_file))
                elif len(line.split(' ')) == 12:
                    log.info("input file format detected: mnemonic")
                    return from_mnemonic(line, scrypt_params)
                elif len(lines) > 1:
                    log.info("input file format detected: credentials")
                    return from_credentials(line, lines[1].strip(), scrypt_params)
                else:
                    raise NotImplementedError('unknown input file format.')
            else:
                raise IOError('empty file.')
    except UnicodeDecodeError as e:
        try:
            with open(input_file, 'rb') as file:
                lines = file.readlines()
                if len(lines) > 0:
                    line = lines[0].strip()
                    regex_dewif = re.compile(b'^\x00\x00\x00\x01\x00\x00\x00\x01')
                    regex_p2p = re.compile(b'^\x08\x01\x12@')
                    if re.search(regex_dewif, line):
                        log.info("input file format detected: dewif")
                        if not password:
                            with pynentry.PynEntry() as p:
                                p.description = f"""Data in DEWIF file is encrypted.
                                Please enter a password to decrypt seed.
                                """
                                p.prompt = 'Passphrase:'
                                try:
                                    password = p.get_pin()
                                except pynentry.PinEntryCancelled:
                                    log.warning('Cancelled! Goodbye.')
                                    exit(1)
                        return from_duniterpy(duniterpy.key.SigningKey.from_dewif_file(input_file, password))
                    if re.search(regex_p2p, line):
                        log.info("input file format detected: p2p")
                        return from_libp2p(line)
                    else:
                        raise NotImplementedError('unknown input file format.')
                else:
                    raise IOError('empty file.')
        except Exception as e:
            log.error(f'Unable to get key from input file {input_file}: {e}')
            exit(2)
    except Exception as e:
        log.error(f'Unable to get key from input file {input_file}: {e}')
        exit(2)

def from_gpg(_gpg, username, password=None):
    log.debug("key.from_gpg(%s, %s, %s)" % (_gpg, username, password))
    try:
        secret_keys = list(_gpg.keylist(pattern=username, secret=True))
        log.debug("key.secret_keys=%s" % secret_keys)
        if not secret_keys:
            log.warning(f"""Unable to find any key matching "{username}".""")
            exit(1)
        else:
            _gpg.secret_key = secret_keys[0]
            log.info(f"""Found key id "{_gpg.secret_key.fpr}" matching "{username}".""")
        log.debug("key._gpg.secret_key.expired=%s" % _gpg.secret_key.expired)
        log.debug("key._gpg.secret_key.fpr=%s" % _gpg.secret_key.fpr)
        log.debug("key._gpg.secret_key.revoked=%s" % _gpg.secret_key.revoked)
        log.debug("key._gpg.secret_key.uids=%s" % _gpg.secret_key.uids)
        log.debug("key._gpg.secret_key.owner_trust=%s" % _gpg.secret_key.owner_trust)
        log.debug("key._gpg.secret_key.last_update=%s" % _gpg.secret_key.last_update)
        if password:
            gpg_passphrase_cb = gpg_passphrase(password).cb
            _gpg.set_passphrase_cb(gpg_passphrase_cb)
            _gpg.set_pinentry_mode(gpg.constants.PINENTRY_MODE_LOOPBACK)
        _gpg.public_armor = _gpg.key_export(_gpg.secret_key.fpr)
        _gpg.secret_armor = _gpg.key_export_secret(_gpg.secret_key.fpr)
        if not _gpg.secret_armor:
            log.error(f"""Unable to export gpg secret key id "{_gpg.secret_key.fpr}" for username "{username}". Please check your password!""")
            exit(2)
        with warnings.catch_warnings():
            # remove CryptographyDeprecationWarning about deprecated
            # SymmetricKeyAlgorithm IDEA, CAST5 and Blowfish (PGPy v0.5.4)
            warnings.simplefilter('ignore')
            _pgpy, _ = pgpy.PGPKey.from_blob(_gpg.secret_armor)
        key = from_pgpy(_pgpy, password)
        key.gpg = _gpg
        return key
    except Exception as e:
        log.error(f'Unable to get key from gpg: {e}')
        exit(2)

def from_jwk(jwk):
    log.debug("key.from_jwk(%s)" % jwk)
    key = ed25519.from_jwk(jwk)
    key.jwk = jwk
    return key

def from_libp2p(libp2p):
    log.debug("key.from_libp2p(%s)" % libp2p)
    return ed25519.from_libp2p(libp2p)

def from_mnemonic(mnemonic, scrypt_params=None):
    log.debug("key.from_mnemonic(%s, %s)" % (mnemonic, scrypt_params))
    try:
        return from_duniterpy(duniterpy.key.SigningKey.from_dubp_mnemonic(
            mnemonic,
            scrypt_params
        ))
    except Exception as e:
        log.error(f'Unable to get key from mnemonic: {e}')
        exit(2)

def from_pem(pem):
    log.debug("key.from_pem(%s)" % pem)
    return ed25519.from_pem(pem)

def from_pgpy(_pgpy, password=None):
    log.debug("key.from_pgpy(%s, %s)" % (_pgpy, password))
    try:
        log.debug("key._pgpy.fingerprint.keyid=%s" % _pgpy.fingerprint.keyid)
        log.debug("key._pgpy.is_protected=%s" % _pgpy.is_protected)
        _pgpy.key_type = pgpy_key_type(_pgpy)
        if _pgpy.is_protected:
            if not password:
                with pynentry.PynEntry() as p:
                    p.description = f"""The exported pgp key id "{_pgpy.fingerprint.keyid}" is password protected.
                    Please enter the passphrase again to unlock it.
                    """
                    p.prompt = 'Passphrase:'
                    try:
                        password = p.get_pin()
                    except pynentry.PinEntryCancelled:
                        log.warning('Cancelled! Goodbye.')
                        exit(1)
            try:
                with warnings.catch_warnings():
                    # remove CryptographyDeprecationWarning about deprecated
                    # SymmetricKeyAlgorithm IDEA, CAST5 and Blowfish (PGPy v0.5.4)
                    warnings.simplefilter('ignore')
                    with _pgpy.unlock(password):
                        assert _pgpy.is_unlocked
                        log.debug("key._pgpy.is_unlocked=%s" % _pgpy.is_unlocked)
                        key = ed25519.from_pgpy(_pgpy)
            except Exception as e:
                log.error(f"""Unable to unlock pgp secret key id "{pgpy.fingerprint.keyid}": {e}""")
                exit(2)
        else:
            key = ed25519.from_pgpy(_pgpy)
        key.pgpy = _pgpy
        return key
    except Exception as e:
        log.error(f'Unable to get key from pgpy: {e}')
        exit(2)

def pgpy_key_type(_pgpy):
    log.debug("key.pgpy_key_type(%s)" % _pgpy)
    if isinstance(_pgpy._key.keymaterial, pgpy.packet.fields.RSAPriv):
        key_type = 'RSA'
    elif isinstance(_pgpy._key.keymaterial, pgpy.packet.fields.DSAPriv):
        key_type = 'DSA'
    elif isinstance(_pgpy._key.keymaterial, pgpy.packet.fields.ElGPriv):
        key_type = 'ElGamal'
    elif isinstance(_pgpy._key.keymaterial, pgpy.packet.fields.ECDSAPriv):
        key_type = 'ECDSA'
    elif isinstance(_pgpy._key.keymaterial, pgpy.packet.fields.EdDSAPriv):
        key_type = 'EdDSA'
    elif isinstance(_pgpy._key.keymaterial, pgpy.packet.fields.ECDHPriv):
        key_type = 'ECDH'
    else:
        key_type = 'undefined'
    log.debug("key.pgpy_key_type().key_type=%s" % key_type)
    return key_type

class gpg_passphrase():
    def __init__(self, password):
        log.debug("gpg_passphrase().__init__(%s)" % password)
        self.password = password

    def cb(self, uid_hint, passphrase_info, prev_was_bad):
        log.debug("gpg_passphrase().cb(%s, %s, %s)" % (uid_hint, passphrase_info, prev_was_bad))
        return self.password

class key():
    def __init__(self):
        log.debug("key().__init__()")
        self.algorithm = 'undefined'
        self.cryptography = None

    def __del__(self):
        log.debug("key().__del__()")
        self._cleanup()

    def _cleanup(self):
        log.debug("key()._cleanup()")
        if hasattr(self, 'duniterpy'):
            if hasattr(self.duniterpy, 'seed') and self.duniterpy.seed:
                clearmem(self.duniterpy.seed)
                log.debug("cleared: key().duniterpy.seed")
            if hasattr(self.duniterpy, 'sk') and self.duniterpy.sk:
                clearmem(self.duniterpy.sk)
                log.debug("cleared: key().duniterpy.sk")
        if hasattr(self, 'gpg'):
            if hasattr(self.gpg, 'secret_armor') and self.gpg.secret_armor:
                clearmem(self.gpg.secret_armor)
                log.debug("cleared: key().gpg.secret_armor")
        if hasattr(self, 'jwk'):
            if hasattr(self, 'secret_jwk') and self.secret_jwk:
                clearmem(self.secret_jwk)
                log.debug("cleared: key().secret_jwk")
            if hasattr(self.jwk, 'd') and self.jwk.d:
                clearmem(self.jwk.d)
                log.debug("cleared: key().jwk.d")
        if hasattr(self, 'pgpy'):
            if hasattr(self.pgpy._key.keymaterial, 'p') and self.pgpy._key.keymaterial.p and not isinstance(self.pgpy._key.keymaterial.p, pgpy.packet.fields.ECPoint):
                clearmem(self.pgpy._key.keymaterial.p)
                log.debug("cleared: key().pgpy._key.material.p")
            if hasattr(self.pgpy._key.keymaterial, 'q') and self.pgpy._key.keymaterial.q:
                clearmem(self.pgpy._key.keymaterial.q)
                log.debug("cleared: key().pgpy._key.material.q")
            if hasattr(self.pgpy._key.keymaterial, 's') and self.pgpy._key.keymaterial.s:
                clearmem(self.pgpy._key.keymaterial.s)
                log.debug("cleared: key().pgpy._key.material.s")
        if hasattr(self, 'secret_b36mf') and self.secret_b36mf:
            clearmem(self.secret_b36mf)
            log.debug("cleared: key().secret_b36mf")
        if hasattr(self, 'secret_b58mf') and self.secret_b58mf:
            clearmem(self.secret_b58mf)
            log.debug("cleared: key().secret_b58mf")
        if hasattr(self, 'secret_b58mh') and self.secret_b58mh:
            clearmem(self.secret_b58mh)
            log.debug("cleared: key().secret_b58mh")
        if hasattr(self, 'secret_b64mh') and self.secret_b64mh:
            clearmem(self.secret_b64mh)
            log.debug("cleared: key().secret_b64mh")
        if hasattr(self, 'secret_base58') and self.secret_base58:
            clearmem(self.secret_base58)
            log.debug("cleared: key().secret_base58")
        if hasattr(self, 'secret_base64') and self.secret_base64:
            clearmem(self.secret_base64)
            log.debug("cleared: key().secret_base64")
        if hasattr(self, 'secret_cidv1') and self.secret_cidv1:
            clearmem(self.secret_cidv1)
            log.debug("cleared: key().secret_cidv1")
        if hasattr(self, 'secret_libp2p') and self.secret_libp2p:
            clearmem(self.secret_libp2p)
            log.debug("cleared: key().secret_libp2p")
        if hasattr(self, 'secret_pem_pkcs8') and self.secret_pem_pkcs8:
            clearmem(self.secret_pem_pkcs8)
            log.debug("cleared: key().secret_pem_pkcs8")
        if hasattr(self, 'secret_proto2') and self.secret_proto2:
            clearmem(self.secret_proto2)
            log.debug("cleared: key().secret_proto2")

    def to_b36mf(self):
        log.debug("key().to_b36mf()")
        if not hasattr(self, 'public_cidv1') or not hasattr(self, 'secret_cidv1'):
            self.to_cidv1()
        try:
            self.public_b36mf = 'k' + base36.dumps(int.from_bytes(self.public_cidv1, byteorder='big'))
            self.secret_b36mf = 'k' + base36.dumps(int.from_bytes(self.secret_cidv1, byteorder='big'))
        except Exception as e:
            log.error(f'Unable to get b36mf from cidv1: {e}')
            exit(2)
        log.debug("key().public_b36mf=%s" % self.public_b36mf)
        log.debug("key().secret_b36mf=%s" % self.secret_b36mf)

    def to_b58mf(self):
        log.debug("key().to_b58mf()")
        if not hasattr(self, 'public_cidv1') or not hasattr(self, 'secret_cidv1'):
            self.to_cidv1()
        try:
            self.public_b58mf = 'z' + base58.b58encode(self.public_cidv1).decode('ascii')
            self.secret_b58mf = 'z' + base58.b58encode(self.secret_cidv1).decode('ascii')
        except Exception as e:
            log.error(f'Unable to get b58mf from cidv1: {e}')
            exit(2)
        log.debug("key().public_b58mf=%s" % self.public_b58mf)
        log.debug("key().secret_b58mf=%s" % self.secret_b58mf)

    def to_b58mh(self):
        log.debug("key().to_b58mh()")
        if not hasattr(self, 'public_libp2p') or not hasattr(self, 'secret_libp2p'):
            self.to_libp2p()
        try:
            self.public_b58mh = base58.b58encode(self.public_libp2p).decode('ascii')
            self.secret_b58mh = base58.b58encode(self.secret_libp2p).decode('ascii')
        except Exception as e:
            log.error(f'Unable to get b58mh from libp2p: {e}')
            exit(2)
        log.debug("key().public_b58mh=%s" % self.public_b58mh)
        log.debug("key().secret_b58mh=%s" % self.secret_b58mh)

    def to_b64mh(self):
        log.debug("key().to_b64mh()")
        if not hasattr(self, 'public_libp2p') or not hasattr(self, 'secret_libp2p'):
            self.to_libp2p()
        try:
            self.public_b64mh = base64.b64encode(self.public_libp2p).decode('ascii')
            self.secret_b64mh = base64.b64encode(self.secret_libp2p).decode('ascii')
        except Exception as e:
            log.error(f'Unable to get b64mh from libp2p: {e}')
            exit(2)
        log.debug("key().public_b64mh=%s" % self.public_b64mh)
        log.debug("key().secret_b64mh=%s" % self.secret_b64mh)

    def to_base58(self):
        log.debug("key().to_base58()")
        try:
            self.public_base58 = base58.b58encode(self.public_bytes).decode('ascii')
            self.secret_base58 = base58.b58encode(self.secret_bytes).decode('ascii')
        except Exception as e:
            log.error(f'Unable to get base58: {e}')
            exit(2)
        log.debug("key().public_base58=%s" % self.public_base58)
        log.debug("key().secret_base58=%s" % self.secret_base58)

    def to_base64(self):
        log.debug("key().to_base64()")
        try:
            self.public_base64 = base64.b64encode(self.public_bytes).decode('ascii')
            self.secret_base64 = base64.b64encode(self.secret_bytes).decode('ascii')
        except Exception as e:
            log.error(f'Unable to get base64: {e}')
            exit(2)
        log.debug("key().public_base64=%s" % self.public_base64)
        log.debug("key().secret_base64=%s" % self.secret_base64)

    def to_cidv1(self):
        log.debug("key().to_cidv1()")
        if not hasattr(self, 'public_libp2p') or not hasattr(self, 'secret_libp2p'):
            self.to_libp2p()
        try:
            # \x01: multicodec cid prefix = CIDv1
            # \x72: multicodec content prefix = libp2p-key
            self.public_cidv1 = b'\x01\x72' + self.public_libp2p
            self.secret_cidv1 = b'\x01\x72' + self.secret_libp2p
        except Exception as e:
            log.error(f'Unable to get cidv1: {e}')
            exit(2)
        log.debug("key().public_cidv1=%s" % self.public_cidv1)
        log.debug("key().secret_cidv1=%s" % self.secret_cidv1)

    def to_duniterpy(self):
        log.debug("key().to_duniterpy()")
        raise NotImplementedError(f"key().to_duniterpy() is not implemented for algorithm {self.algorithm}")

    def to_file(self, output_file, file_format=None, password=None):
        log.debug("key().to_file(%s, %s, %s)" % (output_file, file_format, password))
        try:
            if file_format == 'dewif':
                if not hasattr(self, 'duniterpy'):
                    self.to_duniterpy()
                if not password:
                    with pynentry.PynEntry() as p:
                        p.description = f"""Data in DEWIF file needs to be encrypted.
                        Please enter a password to encrypt seed.
                        """
                        p.prompt = 'Passphrase:'
                        try:
                            password = p.get_pin()
                        except pynentry.PinEntryCancelled:
                            log.warning('Cancelled! Goodbye.')
                            exit(1)
                self.duniterpy.save_dewif_v1_file(output_file, password)
            elif file_format == 'ewif':
                if not hasattr(self, 'duniterpy'):
                    self.to_duniterpy()
                if not password:
                    with pynentry.PynEntry() as p:
                        p.description = f"""Data in EWIF file needs to be encrypted.
                        Please enter a password to encrypt seed.
                        """
                        p.prompt = 'Passphrase:'
                        try:
                            password = p.get_pin()
                        except pynentry.PinEntryCancelled:
                            log.warning('Cancelled! Goodbye.')
                            exit(1)
                self.duniterpy.save_ewif_file(output_file, password)
            elif file_format == 'jwk':
                if not hasattr(self, 'jwk'):
                    self.to_jwk()
                with open(output_file, "w") as file:
                    file.write(self.jwk.export())
            elif file_format == 'nacl':
                if not hasattr(self, 'duniterpy'):
                    self.to_duniterpy()
                self.duniterpy.save_private_key(output_file)
            elif file_format == 'p2p':
                if not hasattr(self, 'secret_libp2p'):
                    self.to_libp2p()
                with open(output_file, "wb") as file:
                    file.write(self.secret_libp2p)
            elif file_format == 'pubsec':
                if not hasattr(self, 'duniterpy'):
                    self.to_duniterpy()
                self.duniterpy.save_pubsec_file(output_file)
            elif file_format == 'seed':
                if not hasattr(self, 'duniterpy'):
                    self.to_duniterpy()
                self.duniterpy.save_seedhex_file(output_file)
            elif file_format == 'wif':
                if not hasattr(self, 'duniterpy'):
                    self.to_duniterpy()
                self.duniterpy.save_wif_file(output_file)
            else:
                if not hasattr(self, 'secret_pem_pkcs8'):
                    self.to_pem_pkcs8()
                with open(output_file, "w") as file:
                    file.write(self.secret_pem_pkcs8)
        except Exception as e:
            log.error(f'Unable to write key to output file {output_file}: {e}')
            exit(2)

    def to_jwk(self):
        log.debug("key().to_jwk()")
        try:
            if not hasattr(self, 'jwk'):
                self.jwk = JWK.from_pyca(self.cryptography)
            self.public_jwk = self.jwk.export_public()
            self.secret_jwk = self.jwk.export_private()
        except Exception as e:
            log.error(f'Unable to get jwk: {e}')
            exit(2)

    def to_libp2p(self):
        log.debug("key().to_libp2p()")
        try:
            if not hasattr(self, 'public_proto2') or not hasattr(self, 'secret_proto2'):
                self.to_proto2()
            # \x00: multihash prefix = raw id
            # \x24: multihash length = 36 bytes
            self.public_libp2p = b'\x00$' + self.public_proto2
            self.secret_libp2p = self.secret_proto2
        except Exception as e:
            log.error(f'Unable to get libp2p: {e}')
            exit(2)
        log.debug("key().public_libp2p=%s" % self.public_libp2p)
        log.debug("key().secret_libp2p=%s" % self.secret_libp2p)

    def to_pem_pkcs8(self):
        log.debug("key().to_pem_pkcs8()")
        try:
            self.secret_pem_pkcs8 = self.cryptography.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('ascii')
        except Exception as e:
            log.error(f'Unable to get pem pkcs8: {e}')
            exit(2)
        log.debug("key().secret_pem_pkcs8=%s" % self.secret_pem_pkcs8)

    def to_proto2(self):
        log.debug("key().to_proto2()")
        raise NotImplementedError(f"key().to_proto2() is not implemented for algorithm {self.algorithm}")

