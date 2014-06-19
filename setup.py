import os

try:
  from setuptools import setup
except:
  from distutils.core import setup


setup(name = "clrypt",
      version = "0.1.6",
      description = "A tool to encrypt/decrypt files.",
      author = "Color Genomics",
      author_email = "dev@getcolor.com",
      url = "https://github.com/ColorGenomics/clrypt",
      packages = ["clrypt"],
      install_requires=[
        'M2Crypto>=0.22.3',
        'PyYAML>=3.10',
      ],
      license = "MIT",
      )
