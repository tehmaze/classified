from distutils.core import setup, Extension
import sys


ext_modules = [
    Extension('classified._platform',
        ['src/classified._platform.c'],
        extra_compile_args=[
            '-DPLATFORM_%s' % (sys.platform.upper()),
        ]
    )
]


setup(
    name         = 'classified',
    version      = '0.0.2',
    author       = 'Wijnand Modderman',
    author_email = 'maze@pyth0n.org',
    description  = 'Classified data scanner',
    license      = 'MIT',
    keywords     = 'classified sensitive pan pci',
    packages     = [
        'classified',
        'classified.probe',
    ],
    data_files   = [
        ('/etc/classified', 'etc/classified.conf.sample'),
    ],
    scripts      = ['bin/classified'],
    ext_modules  = ext_modules,
)

