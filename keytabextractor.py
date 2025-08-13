#!/usr/bin/env python3
import struct
import sys
import argparse
import binascii
from pathlib import Path
from collections import defaultdict

BANNER = r"""
.-. .-')    ('-.             .-') *     ('-.   .-. .-')   ('-. ) (`-.     .-') *  *  .-')    ('-.             .-') *              _  .-')   
\  ( OO ) *(  OO)           (  OO) )   ( OO ).-\  ( OO )*(  OO) ( OO ).  (  OO) )( \( -O )  ( OO ).-.        (  OO) )            ( \( -O )  
,--. ,--.(,------.,--.   ,--/     '._  / . --. /;-----.(,------(_/.  \_)-/     '._,------.  / . --. /  .-----/     '._ .-'),-----.,------.  
|  .'   / |  .---' \  `.'  /|'--...__) | \-.  \ | .-.  ||  .---'\  `.'  /|'--...__|   /`. ' | \-.  \  '  .--.|'--...__( OO'  .-.  |   /`. ' 
|      /, |  |   .-')     / '--.  .--.-'-'  |  || '-' /_|  |     \     /\'--.  .--|  /  | .-'-'  |  | |  |('-'--.  .--/   |  | |  |  /  | | 
|     ' *(|  '--(OO  \   /     |  |   \| |*.'  || .-. `(|  '--.   \   \ |   |  |  |  |_.' |\| |_.'  |/_) |OO  ) |  |  \_) |  |\|  |  |_.' | 
|  .   \  |  .--'|   /  /\_    |  |    |  .-.  || |  \  |  .--'  .'    \_)  |  |  |  .  '.' |  .-.  |||  |`-'|  |  |    \ |  | |  |  .  '.' 
|  |\   \ |  `---`-./  /.__)   |  |    |  | |  || '--'  |  `---./  .'.  \   |  |  |  |\  \  |  | |  (_'  '--'\  |  |     `'  '-'  |  |\  \  
`--' '--' `------' `--'        `--'    `--' `--'`------'`------'--'   '--'  `--'  `--' '--' `--' `--'  `-----'  `--'       `-----'`--' '--' 
 KeyTabExtractor - Extract Keys from KeyTab Files
 Author: h4rry1337 x)
"""

ETYPE_INFO = {
    23: ("RC4-HMAC (NTLM)", 13100, "nt", "ntlm"),
    17: ("AES128-CTS-HMAC-SHA1-96", 19600, "krb5tgs", "aes128"),
    18: ("AES256-CTS-HMAC-SHA1-96", 19700, "krb5tgs", "aes256"),
    3:  ("DES-CBC-MD5", None, "des", "des"),
    16: ("DES3-CBC-SHA1", None, "des3", "des3"),
    1:  ("DES-CBC-CRC", None, "des", "des"),
}

PRINCIPAL_TYPE_MAP = {
    1: "KRB5_NT_PRINCIPAL",
    2: "KRB5_NT_SRV_INST",
    3: "KRB5_NT_SRV_HST",
    4: "KRB5_NT_SRV_XHST",
    5: "KRB5_NT_UID",
    6: "KRB5_NT_ENTERPRISE",
}

def safe_unpack(fmt, data, idx):
    """Safely unpack data with bounds checking"""
    size = struct.calcsize(fmt)
    if idx + size > len(data):
        return None, idx
    return struct.unpack(fmt, data[idx:idx+size])[0], idx + size

def parse_single_entry(entry_data):
    """Parse a single keytab entry (common logic for both versions)"""
    try:
        eidx = 0
        
        # Number of components
        num_comp, eidx = safe_unpack(">H", entry_data, eidx)
        if num_comp is None or num_comp > 100:  # Sanity check
            return None
            
        # Realm
        realm_len, eidx = safe_unpack(">H", entry_data, eidx)
        if realm_len is None or realm_len > 1024 or eidx + realm_len > len(entry_data):
            return None
        realm = entry_data[eidx:eidx+realm_len].decode('utf-8', errors="ignore")
        eidx += realm_len
        
        # Components (principal name parts)
        comps = []
        for _ in range(num_comp):
            comp_len, eidx = safe_unpack(">H", entry_data, eidx)
            if comp_len is None or comp_len > 1024 or eidx + comp_len > len(entry_data):
                return None
            comp = entry_data[eidx:eidx+comp_len].decode('utf-8', errors="ignore")
            comps.append(comp)
            eidx += comp_len
        
        # Principal type (4 bytes)
        principal_type, eidx = safe_unpack(">I", entry_data, eidx)
        if principal_type is None:
            return None
            
        # Timestamp (4 bytes)
        ts, eidx = safe_unpack(">I", entry_data, eidx)
        if ts is None:
            return None
            
        # KVNO - Key Version Number (1 byte)
        if eidx >= len(entry_data):
            return None
        kvno = entry_data[eidx]
        eidx += 1
        
        # Keyblock - keytype (2 bytes)
        keytype, eidx = safe_unpack(">H", entry_data, eidx)
        if keytype is None:
            return None
            
        # Key length (2 bytes)
        keylen, eidx = safe_unpack(">H", entry_data, eidx)
        if keylen is None or keylen > 1024 or eidx + keylen > len(entry_data):
            return None
            
        keybytes = entry_data[eidx:eidx+keylen]
        
        return {
            "realm": realm,
            "components": comps,
            "principal_type": PRINCIPAL_TYPE_MAP.get(principal_type, f"Unknown({principal_type})"),
            "kvno": kvno,
            "etype": keytype,
            "key": keybytes,
            "entry_size": eidx + keylen  # Total size consumed
        }
    except Exception as e:
        return None

def parse_keytab_0x0502(data_bytes):
    """Parse keytab version 0x0502 (with size fields)"""
    entries = []
    offset = 2  # Skip version bytes
    
    while offset + 4 <= len(data_bytes):
        # Read entry size (4 bytes, big-endian)
        entry_size = struct.unpack(">I", data_bytes[offset:offset+4])[0]
        offset += 4
        
        # Check for valid entry size
        if entry_size == 0 or entry_size > len(data_bytes) - offset:
            break
            
        # Extract entry data
        entry_data = data_bytes[offset:offset+entry_size]
        offset += entry_size
        
        # Parse the entry
        parsed = parse_single_entry(entry_data)
        if parsed:
            entries.append(parsed)
    
    return entries

def parse_keytab_0x0501(data_bytes):
    """Parse keytab version 0x0501 (without size fields)"""
    entries = []
    offset = 2  # Skip version bytes
    
    while offset < len(data_bytes):
        # Try to parse an entry starting at current offset
        remaining = data_bytes[offset:]
        if len(remaining) < 10:  # Minimum viable entry size
            break
            
        parsed = parse_single_entry(remaining)
        if parsed:
            entries.append(parsed)
            offset += parsed["entry_size"]
        else:
            # If parsing fails, try to skip forward and find next valid entry
            offset += 1
            
            # Look for potential start of next entry
            found_next = False
            for skip_offset in range(offset, min(offset + 100, len(data_bytes) - 10)):
                test_parsed = parse_single_entry(data_bytes[skip_offset:])
                if test_parsed:
                    offset = skip_offset
                    found_next = True
                    break
            
            if not found_next:
                break
    
    return entries

def parse_keytab_entries(data_bytes):
    """Main parser that detects version and delegates to appropriate parser"""
    if len(data_bytes) < 2:
        return []
    
    version = struct.unpack(">H", data_bytes[0:2])[0]
    
    if version == 0x0502:
        return parse_keytab_0x0502(data_bytes)
    elif version == 0x0501:
        return parse_keytab_0x0501(data_bytes)
    else:
        print(f"[!] Warning: Unknown keytab version 0x{version:04x}, attempting 0x0502 format...")
        return parse_keytab_0x0502(data_bytes)

def save_hashes_by_type(base_output, format_type, hash_collections):
    """Save different hash types to separate files"""
    saved_files = []
    
    for hash_type, entries in hash_collections.items():
        if not entries:
            continue
            
        # Create filename with hash type suffix
        base_path = Path(base_output)
        stem = base_path.stem
        suffix = base_path.suffix if base_path.suffix else ".hashes"
        output_file = base_path.parent / f"{stem}-{hash_type}{suffix}"
        
        lines = []
        for entry in entries:
            if format_type == "hashcat":
                if hash_type == "ntlm":
                    lines.append(entry['hexkey'])
                else:
                    lines.append(f"{entry['principal']}@{entry['realm']}:{entry['etype']}:{entry['hexkey']}")
            else:  # john format
                if hash_type == "ntlm":
                    lines.append(f"$NT${entry['hexkey']}")
                else:
                    lines.append(f"{entry['principal']}@{entry['realm']}:{entry['etype']}:{entry['hexkey']}")
        
        if lines:
            output_file.write_text("\n".join(lines) + "\n")
            saved_files.append((hash_type, str(output_file), len(lines)))
    
    return saved_files

def main():
    parser = argparse.ArgumentParser(prog="keytabextractor.py")
    parser.add_argument("keytab", help=".keytab file (0x0501 / 0x0502)")
    parser.add_argument("-o", "--output", required=True, help="Base output filename (will create multiple files with hash type suffix)")
    parser.add_argument("--format", choices=["hashcat", "john"], required=True, help="Target output format")
    parser.add_argument("--verbose", action="store_true", help="Show detailed parsing information")
    args = parser.parse_args()
    
    path = Path(args.keytab)
    if not path.exists():
        print(f"[!] Error: file '{args.keytab}' not found.")
        sys.exit(1)
    
    print(BANNER)
    
    data = path.read_bytes()
    if len(data) < 2:
        print("[!] File too small or not a keytab.")
        sys.exit(1)
        
    version = struct.unpack(">H", data[0:2])[0]
    print(f"[+] Detected KeyTab version: 0x{version:04x}")
    
    if version == 0x0501:
        print("[+] Using parser for KeyTab format 0x0501 (no size fields)")
    elif version == 0x0502:
        print("[+] Using parser for KeyTab format 0x0502 (with size fields)")
    else:
        print(f"[!] Unknown version, will attempt to parse as 0x0502")
    print()
    
    # Structure to hold all entries organized by encryption type
    entries_by_type = defaultdict(list)
    hash_collections = defaultdict(list)  # For saving to files
    
    # Parse all entries
    parsed_entries = parse_keytab_entries(data)
    
    if args.verbose:
        print(f"[DEBUG] Total raw entries parsed: {len(parsed_entries)}\n")
    
    for entry in parsed_entries:
        principal = "/".join(entry["components"])
        realm = entry["realm"]
        etype = entry["etype"]
        hexkey = binascii.hexlify(entry["key"]).decode()
        
        etinfo = ETYPE_INFO.get(etype, (f"etype-{etype}", None, None, "unknown"))
        etname, hc_mode, john_hint, file_suffix = etinfo
        
        # Store complete entry information
        entry_info = {
            "principal": principal,
            "realm": realm,
            "hexkey": hexkey,
            "etype": etype,
            "hc_mode": hc_mode,
            "john_hint": john_hint,
            "full_principal": f"{principal}@{realm}",
            "kvno": entry.get("kvno"),
            "etname": etname
        }
        
        # Categorize by encryption type for display
        if etype == 23:
            entries_by_type["RC4-HMAC"].append(entry_info)
        elif etype == 17:
            entries_by_type["AES128"].append(entry_info)
        elif etype == 18:
            entries_by_type["AES256"].append(entry_info)
        elif etype in [1, 3]:
            entries_by_type["DES"].append(entry_info)
        elif etype == 16:
            entries_by_type["DES3"].append(entry_info)
        else:
            entries_by_type["UNKNOWN"].append(entry_info)
        
        # Store for file saving
        hash_collections[file_suffix].append(entry_info)
    
    # Display results organized by type and user
    if entries_by_type["RC4-HMAC"]:
        print("="*80)
        print("[*] RC4-HMAC Encryption detected (NTLM HASHES)")
        print("="*80)
        
        # Group by user for better display
        users_ntlm = defaultdict(list)
        for entry in entries_by_type["RC4-HMAC"]:
            users_ntlm[entry["full_principal"]].append(entry)
        
        print(f"\n[+] Found {len(users_ntlm)} unique user(s) with NTLM hashes:\n")
        
        for user_idx, (user_principal, user_entries) in enumerate(users_ntlm.items(), 1):
            print(f"  User #{user_idx}: {user_principal}")
            print(f"  REALM: {user_entries[0]['realm']}")
            print(f"  PRINCIPAL: {user_entries[0]['principal']}")
            print(f"  HASH TYPE: [NTLM]")
            
            for hash_idx, entry in enumerate(user_entries, 1):
                print(f"    [NTLM] Hash {hash_idx}: {entry['hexkey']}")
            print()
    
    if entries_by_type["AES256"]:
        print("="*80)
        print("[*] AES256-CTS-HMAC-SHA1-96 keys detected (KERBEROS KEYS)")
        print("="*80)
        
        users_aes256 = defaultdict(list)
        for entry in entries_by_type["AES256"]:
            users_aes256[entry["full_principal"]].append(entry)
        
        print(f"\n[+] Found {len(users_aes256)} unique user(s) with AES256 keys:\n")
        
        for user_idx, (user_principal, user_entries) in enumerate(users_aes256.items(), 1):
            print(f"  User #{user_idx}: {user_principal}")
            print(f"  REALM: {user_entries[0]['realm']}")
            print(f"  PRINCIPAL: {user_entries[0]['principal']}")
            print(f"  HASH TYPE: [AES256-KERBEROS]")
            
            for key_idx, entry in enumerate(user_entries, 1):
                print(f"    [AES256] Key {key_idx}: {entry['hexkey']}")
            print()
    
    if entries_by_type["AES128"]:
        print("="*80)
        print("[*] AES128-CTS-HMAC-SHA1-96 keys detected (KERBEROS KEYS)")
        print("="*80)
        
        users_aes128 = defaultdict(list)
        for entry in entries_by_type["AES128"]:
            users_aes128[entry["full_principal"]].append(entry)
        
        print(f"\n[+] Found {len(users_aes128)} unique user(s) with AES128 keys:\n")
        
        for user_idx, (user_principal, user_entries) in enumerate(users_aes128.items(), 1):
            print(f"  User #{user_idx}: {user_principal}")
            print(f"  REALM: {user_entries[0]['realm']}")
            print(f"  PRINCIPAL: {user_entries[0]['principal']}")
            print(f"  HASH TYPE: [AES128-KERBEROS]")
            
            for key_idx, entry in enumerate(user_entries, 1):
                print(f"    [AES128] Key {key_idx}: {entry['hexkey']}")
            print()
    
    if entries_by_type["DES"]:
        print("="*80)
        print("[*] DES keys detected (LEGACY ENCRYPTION)")
        print("="*80)
        
        users_des = defaultdict(list)
        for entry in entries_by_type["DES"]:
            users_des[entry["full_principal"]].append(entry)
        
        print(f"\n[+] Found {len(users_des)} unique user(s) with DES keys:\n")
        
        for user_idx, (user_principal, user_entries) in enumerate(users_des.items(), 1):
            print(f"  User #{user_idx}: {user_principal}")
            print(f"  HASH TYPE: [DES-LEGACY]")
            for key_idx, entry in enumerate(user_entries, 1):
                print(f"    [DES] Key {key_idx}: {entry['hexkey']}")
        print("\n    [!] Note: DES support for Kerberos cracking may vary across tool versions.\n")
    
    if entries_by_type["DES3"]:
        print("="*80)
        print("[*] DES3-CBC-SHA1 keys detected (LEGACY ENCRYPTION)")
        print("="*80)
        
        users_des3 = defaultdict(list)
        for entry in entries_by_type["DES3"]:
            users_des3[entry["full_principal"]].append(entry)
        
        print(f"\n[+] Found {len(users_des3)} unique user(s) with DES3 keys:\n")
        
        for user_idx, (user_principal, user_entries) in enumerate(users_des3.items(), 1):
            print(f"  User #{user_idx}: {user_principal}")
            print(f"  HASH TYPE: [3DES-LEGACY]")
            for key_idx, entry in enumerate(user_entries, 1):
                print(f"    [3DES] Key {key_idx}: {entry['hexkey']}")
        print("\n    [!] Note: 3DES support for Kerberos cracking may vary across tool versions.\n")
    
    if entries_by_type["UNKNOWN"]:
        print("="*80)
        print("[*] Unknown/unsupported etypes detected")
        print("="*80)
        for idx, entry in enumerate(entries_by_type["UNKNOWN"], 1):
            print(f"  Entry {idx}: {entry['full_principal']}")
            print(f"    Etype: {entry['etype']}")
            print(f"    Key: {entry['hexkey']}")
        print()
    
    # Save output files by hash type
    saved_files = save_hashes_by_type(args.output, args.format, hash_collections)
    
    if saved_files:
        print("="*80)
        print("[+] OUTPUT FILES CREATED")
        print("="*80)
        for hash_type, filepath, count in saved_files:
            print(f"  [{hash_type.upper()}] {filepath} -> {count} hash(es)")
        
        # Show summary
        total_entries = sum(len(entries) for entries in entries_by_type.values())
        print(f"\n[+] Total entries extracted: {total_entries}")
        
        # Count unique users
        all_users = set()
        for entries in entries_by_type.values():
            for entry in entries:
                all_users.add(entry["full_principal"])
        print(f"[+] Unique users found: {len(all_users)}")
        
        print("\n" + "="*80)
        print("[+] HASHCAT/JOHN USAGE GUIDE")
        print("="*80)
        
        if args.format == "hashcat":
            print("\n  Hashcat commands for each hash type:")
            modes_shown = set()
            for hash_type, filepath, count in saved_files:
                if hash_type == "ntlm":
                    print(f"    hashcat -m 1000 -a 0 {filepath} wordlist.txt  # NTLM")
                elif hash_type == "aes256":
                    print(f"    hashcat -m 19700 -a 0 {filepath} wordlist.txt # AES256 (needs TGS ticket)")
                elif hash_type == "aes128":
                    print(f"    hashcat -m 19600 -a 0 {filepath} wordlist.txt # AES128 (needs TGS ticket)")
        else:
            print("\n  John commands for each hash type:")
            for hash_type, filepath, count in saved_files:
                if hash_type == "ntlm":
                    print(f"    john --format=NT {filepath}")
                else:
                    print(f"    john {filepath}  # Requires full Kerberos ticket format")
    else:
        print("[!] No hashes were saved (no supported entries found).")
    
    print(f"\n[+] Parsing completed successfully for KeyTab version 0x{version:04x}")
    print("="*80)

if __name__ == "__main__":
    main()
