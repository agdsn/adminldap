#!/usr/bin/env python2
from setuptools import setup

setup(name='AdminLDAP',
      version='0.1',
      description='Manage AG DSN admins in a OpenLDAP server.',
      author='Sebastian Schrader',
      author_email='sebastian.schrader@wh2.tu-dresden.de',
      packages=['adminldap'],
      include_package_data=True,
      zip_safe=False,
      install_requires=[
            'Flask',
            'Flask-Babel',
            'Flask-Login',
            'Flask-WTF',
            'ldappool',
            'passlib',
            'python-ldap',
            'wrapt',
      ])