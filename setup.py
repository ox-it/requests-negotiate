from distutils.core import setup

setup(
    name='requests-negotiate',
    version='1.0',
    packages=['requests_negotiate'],
    install_requires=['requests', 'python-gssapi'],
)
