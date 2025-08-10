# KeyTabExtractor – Enhanced Fork of KeyTabExtract

This project is an enhanced fork of [KeyTabExtract](https://github.com/sosdave/KeyTabExtract), originally developed to extract valuable information such as Realm, Service Principal, Encryption Type, and NTLM Hash from type 502 `.keytab` files used to authenticate Linux systems to Kerberos.

The main improvement over the original version is the ability to identify and extract multiple hashes from different users from a single type 502 `.keytab` file, while preserving an output format compatible with tools that accept NTLM hashes. The goal remains to facilitate the analysis and extraction of credentials for auditing and security testing, with performance and compatibility improvements.

## Usage
```bash
./keytabextractor.py [file.keytab]
```

## Key Improvements
- Extraction of multiple user hashes from a single type 502 `.keytab` file.
- Preservation of the output format compatible with tools that accept NTLM hashes.
- Retained the simplicity of the original project, with performance and compatibility enhancements.

## Acknowledgements
- https://github.com/sosdave
- https://github.com/twosevenzero
