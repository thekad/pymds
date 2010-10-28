#!/usr/bin/env python
# -*- mode: python; sh-basic-offset: 4; indent-tabs-mode: nil; coding: utf-8 -*-
# vim: tabstop=4 softtabstop=4 expandtab shiftwidth=4 fileencoding=utf-8
#
# pymds setup script
# Copyright 2010, Jorge A Gallegos <kad@blegh.net>

import setuptools

setuptools.setup (
    name = 'pymds',
    version = '0.4',
    package_dir = { '': 'src' },
    packages = setuptools.find_packages('src'),
    zip_safe = True,
    entry_points = {
        'console_scripts': [
            'pymds = pymds.pymds:main',
        ],
    },
    author = 'Tom Pinckney',
    description = 'An authoritative-only DNS server with a pluggable architecture for determining how to resolve each request',
    license = 'MIT',
    keywords = 'dns authoritativednsserver geodns dnsloadbalancer',
    url = 'http://code.google.com/p/pymds/',
)
