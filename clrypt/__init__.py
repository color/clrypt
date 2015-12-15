import os.path
import threading

from .encdir import EncryptedDirectory
from .openssl import OpenSSLKeypair


_environment = threading.local()


def _get_encdir():
    if not hasattr(_environment, 'encdir'):
        cert_file = os.environ.get('CLRYPT_CERT')
        if cert_file is None:
            raise RuntimeError("The environment variable CLRYPT_CERT must be set")
        if not os.path.isfile(cert_file):
            raise RuntimeError("CLRYPT_CERT points to a non-existent file: %r" % cert_file)

        pk_file = os.environ.get('CLRYPT_PK')
        if pk_file is None:
            raise RuntimeError("The environment variable CLRYPT_PK must be set")
        if not os.path.isfile(pk_file):
            raise RuntimeError("CLRYPT_PK points to a non-existent file: %r" % pk_file)

        encrypted_dir = os.environ.get('ENCRYPTED_DIR')
        if encrypted_dir is None:
            encrypted_dir = _find_encrypted_directory(os.getcwd())
            if encrypted_dir is None:
                raise RuntimeError("Couldn't find an encrypted directory in "
                                   "the current dir or its ancestors")
        if not os.path.isdir(encrypted_dir):
            raise RuntimeError("ENCRYPTED_DIR points to a non-existent "
                               "directory: %r" % encrypted_dir)

        _environment.keypair = OpenSSLKeypair(cert_file, pk_file)
        _environment.encdir = EncryptedDirectory(encrypted_dir,
                                                 _environment.keypair)
    return _environment.encdir


def _find_encrypted_directory(current_dir, dirname='encrypted', limit=100):
    # Stop if the limit has been reached, or we're at the root dir
    if limit == 0 or os.path.dirname(current_dir) == current_dir:
        return None
    elif os.path.isdir(os.path.join(current_dir, dirname)):
        return os.path.join(current_dir, dirname)
    return _find_encrypted_directory(
        os.path.abspath(os.path.dirname(current_dir)),
        dirname=dirname,
        limit=limit - 1)


def read_file(group, name, ext='yaml'):
    """Decrypt and read the named encrypted file."""
    return _get_encdir().read_file(group, name, ext=ext)

def read_file_as_dict(group, name, ext='yaml'):
    """Read the specified encrypted file as a YAML dictionary."""
    return _get_encdir().read_yaml_file(group, name, ext=ext)

def write_file(in_fp, group, name, ext='yaml'):
    """Encrypt and write the contents of in_fp to the named encrypted file."""
    return _get_encdir().write_file(in_fp, group, name, ext=ext)
