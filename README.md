# Classified data scanner

This is work in progress. You can use this utility to scan for classified or
sensitive data, such as PAN information, SSL keys, pcap dumps and so on.

## Requirements

Classified is suitable for Python 2.4 - Python 2.7. With little effort it could
be ported to Python 3.x as well.

Required:
*  [Python 2.4 - 2.7](http://python.org/)

## Optional requirements

Optionally, install:
*  [backports.lzma](http://pypi.python.org/pypi/backports.lzma), to inspect
   LZMA compressed files and archives
*  [rarfile](http://pypi.python.org/pypi/rarfile), to inspect RAR archives


## Installing (Debian, Ubuntu)

You can use [pip](http://www.pip-installer.org/) to install Classified:

    $ sudo apt-get install python-pip python-all-dev
    ...
    $ sudo pip install -e \
        git+https://github.com/tehmaze/classified.git#egg=classified


## Installing (CentOS, Red Hat)

You can use the spec file shipped with Classified:

    $ wget -sO classified.zip \
        https://github.com/tehmaze/classified/archive/master.zip
    $ rpmbuild -ta classified.zip
    ...
    $ sudo rpm -ivh /path/to/classified-x.y.z.arch.rpm


## Bugs/Features

You can use the [issue tracker](https://github.com/tehmaze/classified/issues)
at GitHub.
