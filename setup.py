from distutils.core import setup

setup(
    name='requests-negotiate',
    version='1.3.3',
    description='Negotiate authentication for the requests HTTP client library',
    author='IT Services, University of Oxford',
    author_email='github@it.ox.ac.uk',
    url='https://github.com/ox-it/requests-negotiate',
    license='BSD',
    packages=['requests_negotiate'],
    long_description=open('README.md').read(),
    classifiers=['License :: OSI Approved :: BSD License',
                 'Operating System :: OS Independent',
                 'Programming Language :: Python',
                 'Topic :: Internet :: WWW/HTTP :: Dynamic Content'],
    install_requires=['requests', 'gssapi', 'www-authenticate'],
)
