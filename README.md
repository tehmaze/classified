# Classified data scanner

Classified is a fast forensic tool that aids in scanning for sensitive data,
such as unencrypted PAN (Primary Account Number) data, passwords, network
traffic dumps, and so on. You can use this utility to assist in getting and
maintaining PCI DSS compliance.

## Requirements

Classified is suitable for Python 3.5 - 3.8. Python 2.x is *no longer
supported*.

Required:
*  [Python 3.5 - 3.8](http://python.org/)
*  [python-magic](http://pypi.python.org/pypi/python-magic), for mime type
   detection

## Requirements (optional)

Optionally, install:
*  [backports.lzma](http://pypi.python.org/pypi/backports.lzma), to inspect
   LZMA compressed files and archives
*  [rarfile](http://pypi.python.org/pypi/rarfile), to inspect RAR archives


## Installing (Debian, Ubuntu)

Install the required packages:

    $ sudo apt-get install python-magic python-lzma

You can use [pip](http://www.pip-installer.org/) to install Classified:

    $ sudo apt-get install python-pip python-all-dev
    ...
    $ sudo pip install -e \
        git+https://github.com/tehmaze/classified.git#egg=classified


## Installing (CentOS, Red Hat)

For CentOS and Red Hat Enterprise Linux version 5, you will need to enable the
[Extra Packages for Enterprise Linux](https://fedoraproject.org/wiki/EPEL) and
install:
*  python26
*  python26-devel

You need the following additional Python packages:
*  [python-magic](http://pypi.python.org/pypi/python-magic)


## Usage

The [configuration file](etc/classified.conf.example) has extensive comments
that explains each of the configuration options.


## Bugs/Features

You can use the [issue tracker](https://github.com/tehmaze/classified/issues)
at GitHub.
