# clrypt

A tool to encrypt/decrypt files.

## Getting Started

* Install clrypt
```
$ pip install git+https://git+https://github.com/ColorGenomics/clrypt.git@v0.1.3
```

* Create a directory called `encrypted` in your root directory.

* Set path to encrypted dir.
```
$ export ENCRYPTED_DIR=/path/to/encrypted
```

* Set paths to cert and pk to use for encryption as environment variables.
```
$ export CLRYPT_CERT=/path/to/cert/file.crt
$ export CLRYPT_PK=/path/to/pk/file.pem
```

* Write a encrypted file
```
$ import clrypt
$ file_to_encrypt = open('some_file.txt')
$ clrypt.write_file(file_to_encrypt, 'keys', 'database')
```

* Dencrypted a encrypted file
```
$ import clrypt
$ clrypt.read_file('keys', 'database')
```
