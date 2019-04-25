from builtins import object
import os


class EncryptedDirectory(object):

    """
    An interface to a directory which holds encrypted files.

    This class is used with a keypair (e.g. `clrypt.openssl.OpenSSLKeypair`) to
    manage reading and writing files to an encrypted directory. Files are
    prefixed with the key ID, so one encrypted directory can hold files
    encrypted with multiple keypairs.
    """

    def __init__(self, encrypted_dir, keypair):
        self.encrypted_dir = encrypted_dir
        self.keypair = keypair

    def encrypted_file_path(self, group, name, ext='yaml'):
        """Get the path of an encrypted file with the given group and name."""
        file_name = '%s-%s.%s.smime' % (self.keypair.get_key_id(), name, ext)
        return os.path.join(self.encrypted_dir, group, file_name)

    def read_file(self, group, name, ext='yaml'):
        """Read the named file as a bytestring of decrypted plaintext."""
        with open(self.encrypted_file_path(group, name, ext=ext), mode='rb') as encrypted:
            ciphertext = encrypted.read()
        return self.keypair.decrypt(ciphertext)

    def read_yaml_file(self, group, name, ext='yaml'):
        """Read the named file as decrypted YAML."""
        import yaml
        return yaml.full_load(self.read_file(group, name, ext=ext))

    def write_file(self, in_fp, group, name, ext='yaml'):
        """Encrypt and write the contents of a file-like object to the named file."""

        # Encrypt the entire contents of the input file-like object at once.
        # TODO: investigate passing through in_fp.fileno(), when present.
        encrypted = self.keypair.encrypt(in_fp.read())

        # Ensure the output path exists, creating it if it doesn't.
        out_path = self.encrypted_file_path(group, name, ext)
        dirname = os.path.dirname(out_path)
        if not os.path.isdir(dirname):
            os.makedirs(dirname)

        with open(out_path, 'wb') as out_fp:
            out_fp.write(encrypted)
        return out_path

