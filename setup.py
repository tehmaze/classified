from distutils.core import setup, Extension
import sys


ext_modules = [
    Extension('classified._platform',
        ['src/classified._platform.c'],
        extra_compile_args=[
            '-DPLATFORM_%s' % (sys.platform.upper()),
            '-Wunused',
        ]
    )
]


setup(
    name         = 'classified',
    version      = '1.0.2',
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
    ext_modules  = ext_modules,
)

