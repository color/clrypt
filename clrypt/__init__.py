from  os import environ
import os.path

from .encdir import EncryptedDirectory
from .openssl import OpenSSLKeypair


try:
    ENV_CERT = environ['CLRYPT_CERT']
    ENV_PK = environ['CLRYPT_PK']
except:
    ENV_CERT = None
    ENV_PK = None

try:
    ENCRYPTED_DIR = environ['ENCRYPTED_DIR']
except:
    ENCRYPTED_DIR = None

_KEYPAIR = None
_CLRYPT = None


def read_file(group, name, ext='yaml'):
    """Returns the DECRYPTED keyfile named by the given `group',
    `name' and `ext' (as passed to ``encrypted_file_path'')."""
    return _CLRYPT.read_file(group, name, ext=ext)

def read_file_as_dict(group, name, ext='yaml'):
    return _CLRYPT.read_yaml_file(group, name, ext=ext)

def write_file(in_fp, group, name, ext='yaml'):
    """
    in_fp is an open file-like object
    """
    return _CLRYPT.write_file(in_fp, group, name, ext=ext)

def _find_encrypted_dir(name="encrypted"):
    if ENCRYPTED_DIR:
        return ENCRYPTED_DIR
    path = '.'
    while os.path.split(os.path.abspath(path))[1]:
        dir_path = os.path.join(path, name)
        if os.path.exists(dir_path):
            return os.path.abspath(dir_path)
        path = os.path.join('..', path)
    raise Exception("%s could not be located." % name)


if None not in [ENV_CERT, ENV_PK]:
    _KEYPAIR = OpenSSLKeypair(ENV_CERT, ENV_PK)
    _CLRYPT = EncryptedDirectory(_find_encrypted_dir(), _KEYPAIR)
