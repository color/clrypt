from future import standard_library

standard_library.install_aliases()
from builtins import object
from io import BytesIO
import os.path
import shutil
import unittest

from clrypt.encdir import EncryptedDirectory


TEST_DIR = os.path.join(os.path.abspath(os.path.dirname(__file__)), "test-encdir")


class EncryptedDirectoryTest(unittest.TestCase):
    def setUp(self):
        if not os.path.isdir(TEST_DIR):
            os.makedirs(TEST_DIR)
        self.encdir = EncryptedDirectory(TEST_DIR, DummyKeypair())

    def tearDown(self):
        shutil.rmtree(TEST_DIR)

    def test_encrypted_file_path(self):
        generated_path = self.encdir.encrypted_file_path("dev", "secrets1", ext="yaml")
        self.assertEqual(
            os.path.join(TEST_DIR, "dev", "dummy12345-secrets1.yaml.smime"),
            generated_path,
        )

    def test_read_file(self):
        path = self.encdir.encrypted_file_path("dev", "secrets2", ext="yaml")
        os.makedirs(os.path.dirname(path))
        with open(path, "wb") as fp:
            fp.write(b"E:some secret data")

        plaintext = self.encdir.read_file("dev", "secrets2", ext="yaml")
        self.assertEqual(plaintext, b"some secret data")

    def test_read_yaml_file(self):
        path = self.encdir.encrypted_file_path("dev", "secrets3", ext="yaml")
        os.makedirs(os.path.dirname(path))
        with open(path, "wb") as fp:
            fp.write(b"E:rootKey:\n")
            fp.write(b"  subKey1: value\n")
            fp.write(b"  subKey2: 123\n")

        plainobj = self.encdir.read_yaml_file("dev", "secrets3", ext="yaml")
        self.assertEqual(plainobj, {"rootKey": {"subKey1": "value", "subKey2": 123}})

    def test_write_file(self):
        path = self.encdir.encrypted_file_path("dev", "secrets4", "yaml")
        contents = b"another secret datum"

        self.encdir.write_file(BytesIO(contents), "dev", "secrets4", ext="yaml")
        with open(path, "rb") as fp:
            self.assertEqual(fp.read(), b"E:" + contents)


class DummyKeypair(object):
    def get_key_id(self):
        return "dummy12345"

    def encrypt(self, bytes):
        return b"E:" + bytes

    def decrypt(self, bytes):
        assert bytes.startswith(b"E:")
        return bytes[2:]
