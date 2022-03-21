import os.path
import unittest

import clrypt


## Some directories for testing encrypted directory discovery.
# A directory from which the 'encrypted' dir can be found.
TEST_DIR = os.path.join(os.path.abspath(os.path.dirname(__file__)), "test-clrypt")
# The expected absolute path of the found 'encrypted' dir.
EXPECTED_ENC_DIR = os.path.join(TEST_DIR, "encrypted")
# A subdirectory whose ancestor contains the 'encrypted' dir.
SUB_DIR = os.path.join(TEST_DIR, "subdir", "another_subdir")
# A parent directory -- the 'encrypted' dir will not be discoverable from here.
PARENT_DIR = os.path.dirname(TEST_DIR)

CERT_FILE = os.path.join(
    os.path.abspath(os.path.dirname(__file__)), "test-cert", "test.crt"
)

PK_FILE = os.path.join(
    os.path.abspath(os.path.dirname(__file__)), "test-cert", "test.dem"
)


class TestFindEncryptedDirectory(unittest.TestCase):
    def test_finds_when_in_same_directory(self):
        self.assertEqual(clrypt._find_encrypted_directory(TEST_DIR), EXPECTED_ENC_DIR)

    def test_finds_when_in_parent_directory(self):
        self.assertEqual(clrypt._find_encrypted_directory(SUB_DIR), EXPECTED_ENC_DIR)

    def test_finds_when_in_encrypted_directory(self):
        self.assertEqual(
            clrypt._find_encrypted_directory(EXPECTED_ENC_DIR), EXPECTED_ENC_DIR
        )

    def test_doesnt_find_when_encrypted_dir_is_not_in_ancestor_directory(self):
        self.assertIsNone(clrypt._find_encrypted_directory(PARENT_DIR))


class TestEnvironment(unittest.TestCase):
    """Test that the global clrypt environment (based on os.environ) is managed correctly."""

    def setUp(self):
        self.prev_dir = os.getcwd()

    def tearDown(self):
        for attr in list(vars(clrypt._environment).keys()):
            delattr(clrypt._environment, attr)
        os.chdir(self.prev_dir)

    def test_happy_path(self):
        os.environ["CLRYPT_CERT"] = CERT_FILE
        os.environ["CLRYPT_PK"] = PK_FILE
        os.environ["ENCRYPTED_DIR"] = EXPECTED_ENC_DIR

        decrypted = clrypt.read_file("testing", "content", ext="yml")
        self.assertEqual(decrypted, b"test content")

    def test_happy_path_find_encrypted_dir(self):
        os.environ["CLRYPT_CERT"] = CERT_FILE
        os.environ["CLRYPT_PK"] = PK_FILE
        os.environ.pop("ENCRYPTED_DIR", None)
        os.chdir(TEST_DIR)

        decrypted = clrypt.read_file("testing", "content", ext="yml")
        self.assertEqual(decrypted, b"test content")
