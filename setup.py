#!/usr/bin/env python

from setuptools import setup, find_packages, Extension

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(name='kafl_fuzzer',
      version='0.4',
      description='kAFL/Nyx Kernel Fuzzer',
      maintainer='Steffen Schulz',
      maintainer_email='steffen.schulz@intel.com',
      url='https://github.com/IntelLabs/kAFL',
      install_requires=requirements,
      packages=find_packages(),
      ext_modules = [
          Extension('kafl_fuzzer.native.bitmap',
                    sources = ['kafl_fuzzer/native/bitmap.c'],
                    extra_compile_args=["-O3", "-fPIC", "-mtune=native"],
                    ),
          ],
      scripts = ['kafl_fuzz.py', 'kafl_debug.py',
          'kafl_cov.py', 'kafl_plot.py',
          'kafl_gui.py', 'scripts/mcat.py'],

	  classifiers=[
		  'Development Status :: 4 - Beta',
		  'Environment :: Console',
		  'Intended Audience :: Developers',
		  'Intended Audience :: Science/Research',
		  'License :: OSI Approved :: GNU Affero General Public License v3',
		  'Operating System :: POSIX :: Linux',
		  'Programming Language :: Python'
		  'Topic :: Security',
		  ],
     )
