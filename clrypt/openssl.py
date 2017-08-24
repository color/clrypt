from __future__ import unicode_literals
from builtins import object
import hashlib
import struct
import subprocess
import base64

from pyasn1.codec.der import decoder


class OpenSSLKeypair(object):

    """
    An X509 cert and private key, which can en/decrypt arbitrary bytestrings.
    """

    def __init__(self, cert_filename, key_filename, openssl_bin='openssl'):
        """
        Create a keypair from the provided certificate and key file paths.

        Optionally, override the path to the openssl binary used for
        encryption/decryption.
        """
        self.cert_filename = cert_filename
        self.key_filename = key_filename
        self.openssl_bin = openssl_bin

    def get_key_id(self):
        """
        Get the key ID for this certificate.

        clrypt computes the key ID by taking the MD5 of the certificate's
        public key exponent concatenated with its modulus. Both of these
        numbers are first converted to OpenSSL's multi-precision integer
        format; see `bignum_to_mpi()` for details.
        """
        pubkey_text = subprocess.check_output(
            [self.openssl_bin, 'x509', '-pubkey', '-noout',
             '-in', self.cert_filename])
        modulus, exponent = parse_pubkey(pubkey_text)

        m = hashlib.md5()
        m.update(bignum_to_mpi(exponent))
        m.update(bignum_to_mpi(modulus))
        return m.hexdigest()

    def encrypt(self, plaintext):
        """Encrypt a plaintext bytestring to an S/MIME-encoded bytestring."""
        pipe = subprocess.Popen(
            [self.openssl_bin, 'smime', '-encrypt', '-des3',
             self.cert_filename],
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE)
        encrypted, err = pipe.communicate(input=plaintext)
        if pipe.poll() != 0:
            raise RuntimeError("Error encrypting plaintext: %r" % err)
        return encrypted

    def decrypt(self, ciphertext):
        """Decrypt an S/MIME-encoded bytestring to a plaintext bytestring."""
        pipe = subprocess.Popen(
            [self.openssl_bin, 'smime', '-decrypt',
             '-inkey', self.key_filename,
             '-binary',
             self.cert_filename],
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE)
        decrypted, err = pipe.communicate(input=ciphertext)
        if pipe.poll() != 0:
            raise RuntimeError("Error decrypting ciphertext: %r" % err)
        return decrypted


def bignum_to_mpi(integer):
    """
    Convert an arbitrary-precision Python integer to OpenSSL's multi-precision
    integer byte format.

    See the output of ``man BN_bn2mpi`` for details on the format itself. This
    function is used to get consistent certificate IDs with the previous
    M2Crypto-based version of clrypt.
    """
    bits = integer.bit_length()
    num_bytes = (bits + 7) // 8
    if bits > 0:
        extra = (bits & 0x07) == 0
    length = num_bytes + extra

    if extra:
        if integer < 0:
            integer = abs(integer)
            header = struct.pack('>I', length) + b'\x80'
        else:
            header = struct.pack('>I', length) + b'\x00'
    else:
        header = struct.pack('>I', length)

    return header + int_to_bytearray(integer)


def parse_pubkey(pubkey_s):
    """
    Get the integer modulus and exponent of a provided RSA public key.

    The key should be a string in the format:

        -----BEGIN PUBLIC KEY-----
        ...base64...
        -----END PUBLIC KEY-----
    """
    der_encoded = base64.b64decode(b''.join(pubkey_s.strip().splitlines()[1:-1]))
    rsa_params_encoded = bitstring_to_bytes(decoder.decode(der_encoded)[0][1])
    rsa_params = decoder.decode(rsa_params_encoded)
    modulus, exponent = int(rsa_params[0][0]), int(rsa_params[0][1])
    return (modulus, exponent)

def bitstring_to_bytes(bitstring):
    """Convert PyASN1's strings of 1s and 0s to actual bytestrings."""

    if len(bitstring) % 8 != 0:
        raise ValueError("Unaligned bitstrings cannot be converted to bytes")

    integer = int(''.join(str(x) for x in bitstring), 2)
    return bytes(int_to_bytearray(integer))

def int_to_bytearray(integer):
    # Build a big-endian arbitrary-length representation of the number
    raw_bytes = bytearray()
    while integer > 0:
        raw_bytes.insert(0, integer & 0xff)
        integer = integer >> 8

    return raw_bytes
