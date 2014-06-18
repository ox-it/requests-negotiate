from distutils.core import setup

setup(
    name='requests-negotiate',
    version='1.0',
    license='BSD',
    packages=['requests_negotiate'],
    classifiers=['License :: OSI Approved :: BSD License',
                 'Operating System :: OS Independent',
                 'Programming Language :: Python',
                 'Topic :: Internet :: WWW/HTTP :: Dynamic Content'],
    install_requires=['requests', 'python-gssapi'],
)
