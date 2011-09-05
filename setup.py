#!/usr/bin/env python

import os,glob
from setuptools import setup,find_packages

VERSION='1.0.1'
README = open(os.path.join(os.path.dirname(__file__),'README.txt'),'r').read()

setup(
    name = 'scanreports',
    version = VERSION,
    license = 'PSF',
    keywords = 'Network Utility Functions',
    url = 'https://github.com/hile/scanreports/downloads',
    zip_safe = False,
    install_requires = [ 'setproctitle', 'lxml', 'odfpy' ],
    scripts = glob.glob('bin/*'),
    packages = ['scanreports'],
    author = 'Ilkka Tuohela', 
    author_email = 'hile@iki.fi',
    description = 'Parsers for some security scan report formats',
    long_description = README,

)   

