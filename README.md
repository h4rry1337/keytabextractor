# KeyTabExtractor – Enhanced Fork of KeyTabExtract

This project is an enhanced fork of [KeyTabExtract](https://github.com/sosdave/KeyTabExtract), originally developed to extract valuable information such as Realm, Service Principal, Encryption Type, and NTLM Hash from type 502 `.keytab` files used to authenticate Linux systems to Kerberos.

The main improvement over the original version is the ability to identify and extract multiple hashes from different users from a single type **501 and 502** `.keytab` file, while preserving an output format compatible with tools that accept NTLM hashes. The goal remains to facilitate the analysis and extraction of credentials for auditing and security testing, with performance and compatibility improvements.

## Setup
```bash
$ git clone https://github.com/h4rry1337/keytabextractor.git
$ cd keytabextractor && chmod +x keytabextractor.py
```

## Usage
```bash
usage: keytabextractor.py [-h] -o OUTPUT --format {hashcat,john} [--verbose] keytab

positional arguments:
  keytab                .keytab file (0x0501 / 0x0502)

options:
  -h, --help            show this help message and exit
  -o, --output OUTPUT   Base output filename (will create multiple files with hash type suffix)
  --format {hashcat,john}
                        Target output format
  --verbose             Show detailed parsing information

[*] examples:
./keytabextractor.py [file.keytab]
./keytabextractor.py [file.keytab] --output hashes.txt --format [hashcat/john]
```

## Key Improvements
- Extraction of multiple user hashes from a single type 502 `.keytab` file.
- Preservation of the output format compatible with tools that accept NTLM hashes.
- Retained the simplicity of the original project, with performance and compatibility enhancements.
- Added support for type 501 `.keytab` files.
- Added option to choose output formats (hashcat, john, raw NTLM).
- Improved error handling and verbose logging for debugging.
- Code refactoring for better maintainability and readability.
- Compatibility with Python 3.12+.
- Option to export results directly to a file via CLI arguments.

## Acknowledgements
- https://github.com/sosdave
- https://github.com/twosevenzero
