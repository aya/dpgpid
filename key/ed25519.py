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

from . import key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from SecureBytes import clearmem
import duniterpy.key
import logging as log

def from_duniterpy(duniterpy):
    log.debug("ed25519.from_duniterpy(%s)" % duniterpy)
    try:
        return ed25519(duniterpy.sk[:32])
    except Exception as e:
        log.error(f'Unable to get ed25519 from duniterpy: {e}')
        exit(2)

def from_jwk(jwk):
    log.debug("ed25519.from_jwk(%s)" % jwk)
    try:
        return ed25519(jwk._okp_pri().private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ))
    except Exception as e:
        log.error(f'Unable to get ed25519 from jwk: {e}')
        exit(2)

def from_libp2p(libp2p):
    log.debug("ed25519.from_libp2p(%s) % libp2p")
    try:
        return ed25519(libp2p.lstrip(b'\x08\x01\x12@')[:32])
    except Exception as e:
        log.error(f'Unable to get ed25519 from libp2p: {e}')
        exit(2)

def from_pem(pem):
    log.debug("ed25519.from_pem(%s)" % pem)
    try:
        return ed25519(serialization.load_pem_private_key(pem, password=None).private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ))
    except Exception as e:
        log.error(f'Unable to get ed25519 from pem: {e}')
        exit(2)

def from_pgpy(_pgpy):
    log.debug("ed25519.from_pgpy(%s)" % _pgpy)
    try:
        if _pgpy.key_type == 'RSA':
            log.debug("ed25519._pgpy._key.keymaterial.p=%s" % _pgpy._key.keymaterial.p)
            log.debug("ed25519._pgpy._key.keymaterial.q=%s" % _pgpy._key.keymaterial.q)
            # rsa custom seed: sha256 hash of (p + q), where + is a string concatenation
            # self.ed25519_seed_bytes = nacl.bindings.crypto_hash_sha256((rsa_int).to_bytes(rsa_len,byteorder='big'))
            rsa_int = int(str(_pgpy._key.keymaterial.p) + str(_pgpy._key.keymaterial.q))
            rsa_len = (rsa_int.bit_length() + 7) // 8
            from cryptography.hazmat.primitives import hashes
            digest = hashes.Hash(hashes.SHA256())
            digest.update((rsa_int).to_bytes(rsa_len,byteorder='big'))
            seed =  digest.finalize()
            # seed_bytes = nacl.bindings.crypto_hash_sha256((rsa_int).to_bytes(rsa_len,byteorder='big'))
        elif _pgpy.key_type in ('ECDSA', 'EdDSA', 'ECDH'):
            log.debug("ed25519._pgpy._key.keymaterial.s=%s" % _pgpy._key.keymaterial.s)
            seed = _pgpy._key.keymaterial.s.to_bytes(32, byteorder='big')
        else:
            raise NotImplementedError(f"getting seed from pgpy key type {_pgpy.key_type} is not implemented.")
        return ed25519(seed)
    except Exception as e:
        log.error(f'Unable to get ed25519 from pgpy: {e}')
        exit(2)

class ed25519(key):
    def __init__(self, seed: bytes):
        log.debug("ed25519().__init__(%s)" % seed)
        super().__init__()
        self.algorithm = 'ed25519'
        self.cryptography = Ed25519PrivateKey.from_private_bytes(seed)
        self.public_bytes = self.cryptography.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.secret_bytes = seed + self.public_bytes
        self.seed_bytes = seed

    def _cleanup(self):
        log.debug("ed25519()._cleanup()")
        if hasattr(self, 'secret_bytes') and self.secret_bytes:
            clearmem(self.secret_bytes)
            log.debug("cleared: ed25519().secret_bytes")
        if hasattr(self, 'seed_bytes') and self.seed_bytes:
            clearmem(self.seed_bytes)
            log.debug("cleared: ed25519().seed_bytes")
        super()._cleanup()

    def to_duniterpy(self):
        log.debug("ed25519().to_duniterpy()")
        try:
            if not hasattr(self, 'duniterpy'):
                self.duniterpy = duniterpy.key.SigningKey(self.seed_bytes)
        except Exception as e:
            log.error(f'Unable to get duniterpy: {e}')
            exit(2)
        log.debug("ed25519().duniterpy.seed: %s" % self.duniterpy.seed)

    def to_proto2(self):
        log.debug("ed25519().to_proto2()")
        try:
            ## libp2p Protocol Buffer serialization
            self.public_proto2 = b'\x08\x01\x12 ' + self.public_bytes
            self.secret_proto2 = b'\x08\x01\x12@' + self.secret_bytes
        except Exception as e:
            log.error(f'Unable to get proto2: {e}')
            exit(2)
        log.debug("ed25519().public_proto2=%s" % self.public_proto2)
        log.debug("ed25519().secret_proto2=%s" % self.secret_proto2)

