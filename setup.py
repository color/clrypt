import os

try:
  from setuptools import setup
except:
  from distutils.core import setup


setup(name = "clrypt",
      version = "0.2.3",
      description = "A tool to encrypt/decrypt files.",
      author = "Color Genomics",
      author_email = "dev@getcolor.com",
      url = "https://github.com/color/clrypt",
      packages = ["clrypt"],
      install_requires=[
          'PyYAML>=3.10',
          'pyasn1>=0.1.9',
      ],
      license = "MIT",
     )
