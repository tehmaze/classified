# Classified data scanner

Classified is a fast forensic tool that aids in scanning for sensitive data,
such as unencrypted PAN (Primary Account Number) data, passwords, network
traffic dumps, and so on. You can use this utility to assist in getting and
maintaining PCI DSS compliance.

## Requirements

Classified requires Python 3.9 or later. Python 2.x is *no longer supported*.

Required dependencies (installed automatically via `uv` or `pip`):
*  [python-magic](https://pypi.org/project/python-magic/), for mime type detection
*  [Jinja2](https://pypi.org/project/Jinja2/), for HTML report rendering
*  [rarfile](https://pypi.org/project/rarfile/), to inspect RAR archives

## Installing

Install [uv](https://docs.astral.sh/uv/) if you haven't already:

    $ curl -LsSf https://astral.sh/uv/install.sh | sh

Then install Classified:

    $ uv tool install git+https://github.com/tehmaze/classified.git

Or clone and install in development mode:

    $ git clone https://github.com/tehmaze/classified.git
    $ cd classified
    $ uv sync


## Installing (CentOS Stream 9, RHEL 9/10, Oracle Linux 9/10)

Install the `libmagic` system library required by `python-magic`:

    $ sudo dnf install -y file-libs

Then install `uv` and Classified:

    $ curl -LsSf https://astral.sh/uv/install.sh | sh
    $ uv tool install git+https://github.com/tehmaze/classified.git

For RAR archive inspection, install `unrar` from the
[RPM Fusion](https://rpmfusion.org/) repository (RHEL/CentOS/Oracle Linux):

    $ sudo dnf install -y epel-release  # skip if already enabled
    $ sudo dnf install -y unar


## Usage

The [configuration file](etc/classified.conf.example) has extensive comments
that explains each of the configuration options.


## Bugs/Features

You can use the [issue tracker](https://github.com/tehmaze/classified/issues)
at GitHub.
