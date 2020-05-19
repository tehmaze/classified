from distutils.core import setup


setup(
    name         = 'classified',
    version      = '1.4.0',
    author       = 'Wijnand Modderman',
    author_email = 'maze@pyth0n.org',
    description  = 'Classified data scanner',
    license      = 'MIT',
    keywords     = 'classified sensitive pan pci',
    packages     = [
        'classified',
        'classified.probe',
        'classified.probe.pan',
        'classified.probe.password',
        'classified.probe.pcap',
        'classified.probe.ssl',
        'classified.report',
    ],
    package_data = {
        'classified': ['template/*/*'],
    },
    data_files   = [
        ('/etc/classified', ['etc/classified.conf.example']),
    ],
    scripts      = ['bin/classified'],
)
