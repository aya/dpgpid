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
    log.debug("ed25519.from_pem()")
    try:
        return ed25519(serialization.load_pem_private_key(pem, password=None).private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ))
    except Exception as e:
        log.error(f'Unable to get ed25519 from pem: {e}')
        exit(2)

def from_pgpy(pgpy):
    log.debug("ed25519.from_pgpy()")
    try:
        self.pgpy_key_type()
        if self.pgpy_key_type == 'RSA':
            log.debug("key.pgpy._key.keymaterial.p=%s" % self.pgpy._key.keymaterial.p)
            log.debug("key.pgpy._key.keymaterial.q=%s" % self.pgpy._key.keymaterial.q)
            # rsa custom seed: sha256 hash of (p + q), where + is a string concatenation
            # self.ed25519_seed_bytes = nacl.bindings.crypto_hash_sha256((rsa_int).to_bytes(rsa_len,byteorder='big'))
            rsa_int = int(str(self.pgpy._key.keymaterial.p) + str(self.pgpy._key.keymaterial.q))
            rsa_len = (rsa_int.bit_length() + 7) // 8
            from cryptography.hazmat.primitives import hashes
            digest = hashes.Hash(hashes.SHA256())
            digest.update((rsa_int).to_bytes(rsa_len,byteorder='big'))
            seed_bytes =  digest.finalize()
            # seed_bytes = nacl.bindings.crypto_hash_sha256((rsa_int).to_bytes(rsa_len,byteorder='big'))
        elif self.pgpy_key_type in ('ECDSA', 'EdDSA', 'ECDH'):
            log.debug("key.pgpy._key.keymaterial.s=%s" % self.pgpy._key.keymaterial.s)
            seed_bytes = self.pgpy._key.keymaterial.s.to_bytes(32, byteorder='big')
        else:
            raise NotImplementedError(f"getting seed from pgp key type {self.pgpy_key_type} is not implemented")
        return ed25519(seed_bytes)
    except Exception as e:
        log.error(f'Unable to get ed25519 from pgpy: {e}')
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

class ed25519(key):
    def __init__(self, seed: bytes):
        super().__init__()
        self.algorithm = 'ed25519'
        self.cryptography = Ed25519PrivateKey.from_private_bytes(seed)
        self.public_bytes = self.cryptography.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.secret_bytes = seed + self.public_bytes
        self.seed_bytes = seed
        log.debug("ed25519().seed_bytes=%s" % self.seed_bytes)

    def _cleanup(self):
        log.debug("ed25519()._cleanup()")
        if hasattr(self, 'duniterpy'):
            if hasattr(self.duniterpy, 'seed') and self.duniterpy.seed:
                clearmem(self.duniterpy.seed)
                log.debug("cleared: ed25519().duniterpy.seed")
            if hasattr(self.duniterpy, 'sk') and self.duniterpy.sk:
                clearmem(self.duniterpy.sk)
                log.debug("cleared: ed25519().duniterpy.sk")
        if hasattr(self, 'secret_b36mf') and self.secret_b36mf:
            clearmem(self.secret_b36mf)
            log.debug("cleared: ed25519().secret_b36mf")
        if hasattr(self, 'secret_b58mf') and self.secret_b58mf:
            clearmem(self.secret_b58mf)
            log.debug("cleared: ed25519().secret_b58mf")
        if hasattr(self, 'secret_b58mh') and self.secret_b58mh:
            clearmem(self.secret_b58mh)
            log.debug("cleared: ed25519().secret_b58mh")
        if hasattr(self, 'secret_b64mh') and self.secret_b64mh:
            clearmem(self.secret_b64mh)
            log.debug("cleared: ed25519().secret_b64mh")
        if hasattr(self, 'secret_base58') and self.secret_base58:
            clearmem(self.secret_base58)
            log.debug("cleared: ed25519().secret_base58")
        if hasattr(self, 'secret_base64') and self.secret_base64:
            clearmem(self.secret_base64)
            log.debug("cleared: ed25519().secret_base64")
        if hasattr(self, 'secret_bytes') and self.secret_bytes:
            clearmem(self.secret_bytes)
            log.debug("cleared: ed25519().secret_bytes")
        if hasattr(self, 'secret_cidv1') and self.secret_cidv1:
            clearmem(self.secret_cidv1)
            log.debug("cleared: ed25519().secret_cidv1")
        if hasattr(self, 'secret_libp2p') and self.secret_libp2p:
            clearmem(self.secret_libp2p)
            log.debug("cleared: ed25519().secret_libp2p")
        if hasattr(self, 'secret_pem_pkcs8') and self.secret_pem_pkcs8:
            clearmem(self.secret_pem_pkcs8)
            log.debug("cleared: ed25519().secret_pem_pkcs8")
        if hasattr(self, 'secret_proto2') and self.secret_proto2:
            clearmem(self.secret_proto2)
            log.debug("cleared: ed25519().secret_proto2")
        if hasattr(self, 'seed_bytes') and self.seed_bytes:
            clearmem(self.seed_bytes)
            log.debug("cleared: ed25519().seed_bytes")
        if hasattr(self, 'ipfs_privkey') and self.ipfs_privkey:
            clearmem(self.ipfs_privkey)
            log.debug("cleared: ed25519().ipfs_privkey")
        if hasattr(self, 'jwk'):
            if hasattr(self, 'secret_jwk') and self.secret_jwk:
                clearmem(self.secret_jwk)
                log.debug("cleared: ed25519().secret_jwk")
            if hasattr(self.jwk, 'd') and self.jwk.d:
                clearmem(self.jwk.d)
                log.debug("cleared: ed25519().jwk.d")
        if hasattr(self, 'pgp_secret_armor') and self.pgp_secret_armor:
            clearmem(self.pgp_secret_armor)
            log.debug("cleared: ed25519().pgp_secret_armor")
        if hasattr(self, 'pgpy'):
            if hasattr(self.pgpy._key.keymaterial, 'p') and self.pgpy._key.keymaterial.p and not isinstance(self.pgpy._key.keymaterial.p, pgpy.packet.fields.ECPoint):
                clearmem(self.pgpy._key.keymaterial.p)
                log.debug("cleared: ed25519().pgpy._key.material.p")
            if hasattr(self.pgpy._key.keymaterial, 'q') and self.pgpy._key.keymaterial.q:
                clearmem(self.pgpy._key.keymaterial.q)
                log.debug("cleared: ed25519().pgpy._key.material.q")
            if hasattr(self.pgpy._key.keymaterial, 's') and self.pgpy._key.keymaterial.s:
                clearmem(self.pgpy._key.keymaterial.s)
                log.debug("cleared: ed25519().pgpy._key.material.s")

    def to_duniterpy(self):
        log.debug("keygen.to_duniterpy()")
        try:
            if not hasattr(self, 'duniterpy'):
                self.duniterpy = duniterpy.key.SigningKey(self.seed_bytes)
        except Exception as e:
            log.error(f'Unable to get duniterpy: {e}')
            exit(2)
        log.debug("keygen.duniterpy.seed: %s" % self.duniterpy.seed)

    def to_proto2(self):
        log.debug("key.to_proto2()")
        try:
            ## libp2p Protocol Buffer serialization
            self.public_proto2 = b'\x08\x01\x12 ' + self.public_bytes
            self.secret_proto2 = b'\x08\x01\x12@' + self.secret_bytes
        except Exception as e:
            log.error(f'Unable to get proto2: {e}')
            exit(2)
        log.debug("key.public_proto2=%s" % self.public_proto2)
        log.debug("key.secret_proto2=%s" % self.secret_proto2)

