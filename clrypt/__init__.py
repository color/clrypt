import hashlib
import os.path
from  os import environ
from M2Crypto import X509, SMIME, BIO


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

def read_file(group, name, ext='yaml', pk=ENV_PK, cert=ENV_CERT):
    """Returns the DECRYPTED keyfile named by the given `group',
    `name' and `ext' (as passed to ``encrypted_file_path'')."""
    s = SMIME.SMIME()
    if not (os.path.exists(pk)):
        raise ValueError('Keypair file does not exist: %s' % pk)
    if not (os.path.exists(cert)):
        raise ValueError('Cert file does not exist: %s' % cert)
    s.load_key(pk, cert)
    encrypted_file = _encrypted_file_path(group, name, ext)
    if not os.path.exists(encrypted_file):
        raise ValueError("Encrypted file %(encrypted_file)s doesn't exist." % locals())
    p7, data = SMIME.smime_load_pkcs7(encrypted_file)
    return s.decrypt(p7)

def read_file_as_dict(group, name, ext='yaml'):
    return _as_dict(read_file(group, name, ext))

def write_file(in_fp, group, name, ext='yaml'):
    """
    in_fp is an open file-like object
    """

    plaintext = BIO.File(in_fp)

    stk = X509.X509_Stack()
    stk.push(X509.load_cert(ENV_CERT))

    s = SMIME.SMIME()
    s.set_x509_stack(stk)
    s.set_cipher(SMIME.Cipher('des_ede3_cbc'))

    p7 = s.encrypt(plaintext)

    outpath = _encrypted_file_path(group, name, ext)
    dirname = os.path.dirname(outpath)
    if not os.path.isdir(dirname):
        os.makedirs(dirname)

    with open(outpath, 'w') as out_fp:
        out = BIO.File(out_fp)
        s.write(out, p7)

    return outpath

def _find_encrypted_dir(name="encrypted"):
    if ENCRYPTED_DIR:
        return ENCRYPTED_DIR
    path = '.'
    while os.path.split(os.path.abspath(path))[1]:
        dir_path = os.path.join(path, name)
        if os.path.exists(dir_path):
            return os.path.abspath(dir_path)
        path = os.path.join('..', path)
    raise Exception("%s could not be located.")

def _encrypted_file_path(group, name, ext='yaml'):
    """Construct a path to the keyfile named by the `group' and
    `name'. `group' is relative to the encrypted directory.
    Optionally specifyan extension."""
    file_name = '%s-%s.%s.smime' % (_id_from_cert(), name, ext)
    return os.path.join(_find_encrypted_dir(), group, file_name)

def _id_from_cert(cert=ENV_CERT):
    """Get the ID of the currently loaded certificate. This is an
    opaque string uniquely identifying the loaded EC2 certificate."""
    cert = X509.load_cert(cert)
    rsa = cert.get_pubkey().get_rsa()
    m = hashlib.md5()
    m.update(rsa.e)
    m.update(rsa.n)
    return m.hexdigest()

def _as_dict(raw_data):
    """Turn keyfile raw data into a simple dict"""
    import yaml
    return yaml.load(raw_data)
