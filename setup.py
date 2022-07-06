from setuptools import setup

setup(
    name='dmarc-imap-report',
    version='1.0.0',
    description='Keep your gandi DNS records up to date with your current IP',
    url='https://github.com/cdidier/dmarc-imap-report',
    author='Colin Didier',
    author_email='cdidier@cybione.org',
    license='MIT',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: System Administrators',
        'Topic :: Communications :: Email',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.6',
    ],
    keywords='dmarc imap',
    py_modules=["dmarc_imap_report"],
    install_requires=["IMAPClient"],
    entry_points={
        'console_scripts': [
            'dmarc-imap-report=dmarc_imap_report:main',
        ],
    },
)
