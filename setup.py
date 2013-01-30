from setuptools import setup

setup(
    name         = 'classified',
    version      = '0.0.1',
    author       = 'Wijnand Modderman',
    author_email = 'maze@pyth0n.org',
    description  = 'Classified data scanner',
    license      = 'MIT',
    keywords     = 'classified sensitive pan pci',
    packages     = [
        'classified',
        'classified.platform',
        'classified.probe',
    ],
    data_files   = [
        ('/etc/classified', 'etc/classified.conf.sample'),
    ],
    scripts      = ['bin/classified'],
)

