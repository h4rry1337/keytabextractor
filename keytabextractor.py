#!/usr/bin/env python3
import binascii
import sys

def banner():
    print(r"""
.-. .-')    ('-.             .-') _     ('-.   .-. .-')   ('-. ) (`-.     .-') _  _  .-')    ('-.             .-') _              _  .-')   
\  ( OO ) _(  OO)           (  OO) )   ( OO ).-\  ( OO )_(  OO) ( OO ).  (  OO) )( \( -O )  ( OO ).-.        (  OO) )            ( \( -O )  
,--. ,--.(,------.,--.   ,--/     '._  / . --. /;-----.(,------(_/.  \_)-/     '._,------.  / . --. /  .-----/     '._ .-'),-----.,------.  
|  .'   / |  .---' \  `.'  /|'--...__) | \-.  \ | .-.  ||  .---'\  `.'  /|'--...__|   /`. ' | \-.  \  '  .--.|'--...__( OO'  .-.  |   /`. ' 
|      /, |  |   .-')     / '--.  .--.-'-'  |  || '-' /_|  |     \     /\'--.  .--|  /  | .-'-'  |  | |  |('-'--.  .--/   |  | |  |  /  | | 
|     ' _(|  '--(OO  \   /     |  |   \| |_.'  || .-. `(|  '--.   \   \ |   |  |  |  |_.' |\| |_.'  |/_) |OO  ) |  |  \_) |  |\|  |  |_.' | 
|  .   \  |  .--'|   /  /\_    |  |    |  .-.  || |  \  |  .--'  .'    \_)  |  |  |  .  '.' |  .-.  |||  |`-'|  |  |    \ |  | |  |  .  '.' 
|  |\   \ |  `---`-./  /.__)   |  |    |  | |  || '--'  |  `---./  .'.  \   |  |  |  |\  \  |  | |  (_'  '--'\  |  |     `'  '-'  |  |\  \  
`--' '--' `------' `--'        `--'    `--' `--'`------'`------'--'   '--'  `--'  `--' '--' `--' `--'  `-----'  `--'       `-----'`--' '--' 

 KeyTabExtractor - Extract NTLM and AES Hashes from KeyTab Files
 Author: h4rry1337 && gabriel gomes x)
    """)

def displayhelp():
    print("Usage : ./keytabextractor.py [keytabfile]")
    print("Example : ./keytabextractor.py service.keytab")
    print("\nSupported formats: RC4-HMAC, AES128, AES256\n")

# Check if the argument was provided before trying to open the file
if len(sys.argv) < 2:
    banner()
    displayhelp()
    sys.exit(1)

ktfile = sys.argv[1]

try:
    f = open(ktfile, 'rb').read()
except FileNotFoundError:
    print(f"[!] Error: file '{ktfile}' not found.")
    sys.exit(1)
except PermissionError:
    print(f"[!] Error: no permission to read the file '{ktfile}'.")
    sys.exit(1)

hex_encoded = binascii.hexlify(f).decode('utf-8')

def ktextractor():
    rc4hmac = aes128 = aes256 = False 

    if '00170010' in hex_encoded:
        print("[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.")
        rc4hmac = True
    else:
        print("[!] No RC4-HMAC located. Unable to extract NTLM hashes.")
        
    if '00120020' in hex_encoded:
        print("[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.")
        aes256 = True
    else:
        print("[!] Unable to identify any AES256-CTS-HMAC-SHA1 hashes.")

    if '00110010' in hex_encoded:
        print("[*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction.")
        aes128 = True
    else:
        print("[!] Unable to identify any AES128-CTS-HMAC-SHA1 hashes.")

    if not any([rc4hmac, aes256, aes128]):
        print("Unable to find any useful hashes.\nExiting...")
        sys.exit()

    # First 16 bits are dedicated to stating the version of Keytab File
    ktversion = hex_encoded[:4]
    if ktversion == '0502':
        print("[+] Keytab File successfully imported.")
    else:
        print("[!] Only Keytab versions 0502 are supported.\nExiting...")
        sys.exit()

    # Realm and Service Principal parsing
    num_realm = int(hex_encoded[16:20], 16)
    realm_jump = 20 + (num_realm * 2)
    realm = hex_encoded[20:realm_jump]
    print("\tREALM : " + bytes.fromhex(realm).decode('utf-8'))

    comp_array_calc  = realm_jump + 4
    comp_array = int(hex_encoded[realm_jump:comp_array_calc], 16)
    comp_array_offset = comp_array_calc + (comp_array * 2)
    comp_array2 = hex_encoded[comp_array_calc:comp_array_offset]

    principal_array_offset = comp_array_offset + 4
    principal_array = hex_encoded[comp_array_offset:principal_array_offset]
    principal_array_int = (int(principal_array, 16) * 2)
    prin_array_start = principal_array_offset
    prin_array_finish = prin_array_start + principal_array_int
    principal_array_value = hex_encoded[prin_array_start:prin_array_finish]
    print("\tSERVICE PRINCIPAL : " + bytes.fromhex(comp_array2).decode('utf-8') + "/" + bytes.fromhex(principal_array_value).decode('utf-8'))

    if rc4hmac:
        print("\n[*] Listing all NTLM (RC4-HMAC) hashes found:")
        rc4_blocks = hex_encoded.split("00170010")[1:]
        for idx, block in enumerate(rc4_blocks):
            ntlm_hash = block[:32]  # 16 bytes = 32 hex chars
            print(f"\tNTLM HASH {idx+1}: {ntlm_hash}")

    if aes256:
        aes256hash = hex_encoded.split("00120020")[1]
        print("\tAES-256 HASH : " + aes256hash[:64])

    if aes128:
        aes128hash = hex_encoded.split("00110010")[1]
        print("\tAES-128 HASH : " + aes128hash[:32])

if __name__ == "__main__":
    banner()
    ktextractor()
