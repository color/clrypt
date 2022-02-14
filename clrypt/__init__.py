import os
import logging
import tempfile
import threading
from pathlib import Path
from typing import Optional

from .encdir import EncryptedDirectory
from .openssl import OpenSSLKeypair

logger = logging.getLogger('clrypt')

_environment = threading.local()


def _load_keypair_from_ssm() -> Optional[OpenSSLKeypair]:
    """Tries to load keypair from aws ssm. Returns None for any failures."""
    key_mode = os.environ.get('COLOR_KEY_MODE')
    if not key_mode:
        return

    try:
        import boto3
        import botocore

        ssm = boto3.client('ssm')

        tempdir = Path(tempfile.gettempdir())

        cert_param_name = f'/clrypt/{key_mode}.crt'
        cert_path = tempdir / cert_param_name[1:]
        pk_param_name = f'/clrypt/{key_mode}.pem'
        pk_path = tempdir / pk_param_name[1:]

        params = ssm.get_parameters(
            Names=[cert_param_name, pk_param_name],
            WithDecryption=True,
        )
        param_values = {p['Name']: p['Value'] for p in params['Parameters']}

        if cert_param_name not in param_values or pk_param_name not in param_values:
            return

        cert_path.parent.mkdir(exist_ok=True)
        cert_path.write_text(param_values[cert_param_name])
        pk_path.write_text(param_values[pk_param_name])

        logging.warning(
            'clrypt keypair was loaded from SSM. This is an EXPERIMENTAL feature. '
            'DO NOT rely on this for production services.'
        )

        return OpenSSLKeypair(cert_path, pk_path)
    except (
        ModuleNotFoundError,
        botocore.exceptions.EndpointConnectionError,
        botocore.exceptions.ClientError,
    ):
        logger.exception('Experimental loading of keypair from ssm failed.')
        # This covers boto3 not being importable, no ssm access, and connection errors.
        return


def _load_keypair_from_env() -> Optional[OpenSSLKeypair]:
    """Tries to load keypair from files referenced in env vars."""
    cert_file = os.environ.get('CLRYPT_CERT')
    if not cert_file:
        return
    cert_file = Path(cert_file).expanduser()
    if not cert_file.is_file():
        return

    pk_file = os.environ.get('CLRYPT_PK')
    if pk_file:
        pk_file = Path(pk_file).expanduser()
    if not pk_file or not pk_file.is_file():
        raise RuntimeError("CLRYPT_PK points to a non-existent file: %r" % pk_file)

    return OpenSSLKeypair(cert_file, pk_file)


def _load_keypair() -> OpenSSLKeypair:
    """Returns a OpenSSLKeypair for decrypting the encrypted dir.

    Currently the only supported method of loading the keypairs is from disk as paths
    specified by CLRYPT_CERT/CLRYPT_PK.

    If this fails, experimental support for fetching from SSM is included.
    """
    keypair = _load_keypair_from_env()
    if keypair:
        return keypair

    keypair = _load_keypair_from_ssm()
    if keypair:
        return keypair

    raise RuntimeError(
        "Can not find clrypt keypair. Please set CLRYPT_PK and CLRYPT_CERT to valid "
        "paths containing the keypair."
    )


def _get_encdir():
    if not hasattr(_environment, 'encdir'):
        encrypted_dir = os.environ.get('ENCRYPTED_DIR')
        if not encrypted_dir:
            encrypted_dir = _find_encrypted_directory(os.getcwd())
            if encrypted_dir is None:
                raise RuntimeError(
                    "Couldn't find an encrypted directory in "
                    "the current dir or its ancestors"
                )
        encrypted_dir = Path(encrypted_dir).expanduser()
        if not encrypted_dir.is_dir():
            raise RuntimeError(
                "ENCRYPTED_DIR points to a non-existent "
                "directory: %r" % encrypted_dir
            )

        _environment.keypair = _load_keypair()
        _environment.encdir = EncryptedDirectory(encrypted_dir, _environment.keypair)
    return _environment.encdir


def _find_encrypted_directory(current_dir, dirname='encrypted', limit=100):
    # Stop if the limit has been reached, or we're at the root dir
    while limit > 0 and os.path.dirname(current_dir) != current_dir:
        if os.path.isdir(os.path.join(current_dir, dirname)):
            return os.path.join(current_dir, dirname)
        current_dir = os.path.abspath(os.path.dirname(current_dir))
        limit -= 1


def read_file(group, name, ext='yaml'):
    """Decrypt and read the named encrypted file."""
    return _get_encdir().read_file(group, name, ext=ext)


def read_file_as_dict(group, name, ext='yaml'):
    """Read the specified encrypted file as a YAML dictionary."""
    return _get_encdir().read_yaml_file(group, name, ext=ext)


def write_file(in_fp, group, name, ext='yaml'):
    """Encrypt and write the contents of in_fp to the named encrypted file."""
    return _get_encdir().write_file(in_fp, group, name, ext=ext)
