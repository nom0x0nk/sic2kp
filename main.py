import argparse
import getpass
import io
import struct
import sys
import zlib
import base64
import os
from datetime import datetime, timezone
from urllib.parse import urlparse

# Third-party imports
import xmltodict
from Cryptodome.Cipher import AES
from passlib.utils import pbkdf2
import pykeepass

    
# -----------------------------------------------------------
# CONFIGURATION: Define Groups and Keywords
# -----------------------------------------------------------
# Matching is case-insensitive. 
# Checks both Title AND Email/Login fields.
# Example: "max" matches "maximus@email.com" or "maxm"

GROUP_RULES = {
    "Finance": ["bank", "insurance", "tax", "finance", "paypal"],
    "Social": ["facebook", "twitter", "instagram", "linkedin", "tiktok", " a "],
    "Shopping": ["amazon", "ebay", "aliexpress", "shop", "store"],
    "Gaming": ["steam", "epic", "origin", "uplay", "battle.net", "blizzard"],
    "Work": ["office", "slack", "zoom", "teams", "work"],
    "Email": ["gmail", "outlook", "webmail", "mail"]
}


# --------------------------------------------------------------------------------
# SafeInCloud Decryption Logic
# --------------------------------------------------------------------------------

class SafeInCloudDecryptor:
    def __init__(self, filename, password):
        self.filename = filename
        self.password = password

    def _get_byte(self, f):
        return struct.unpack("B", f.read(1))[0]

    def _get_short(self, f):
        return struct.unpack("H", f.read(2))[0]

    def _get_array(self, f):
        size = self._get_byte(f)
        return struct.unpack("%ds" % size, f.read(size))[0]

    def decrypt(self):
        with open(self.filename, "rb") as f:
            self._get_short(f)  # magic
            self._get_byte(f)   # sver
            salt = self._get_array(f)
            
            skey = pbkdf2.pbkdf2(self.password, salt, 10000, 32)
            
            iv = self._get_array(f)
            cipher = AES.new(skey, AES.MODE_CBC, iv)
            
            salt2 = self._get_array(f)
            block = self._get_array(f)
            decr = cipher.decrypt(block)
            
            sub_fd = io.BytesIO(decr)
            iv2 = self._get_array(sub_fd)
            pass2 = self._get_array(sub_fd)
            self._get_array(sub_fd)

            cipher = AES.new(pass2, AES.MODE_CBC, iv2)
            data = cipher.decrypt(f.read())

            decompressor = zlib.decompressobj()
            return decompressor.decompress(data) + decompressor.flush()

# --------------------------------------------------------------------------------
# Conversion Logic
# --------------------------------------------------------------------------------

def safe_get(obj, key, default=None):
    if obj is None:
        return default
    return obj.get(key, default)

def parse_timestamp(ts_str):
    if not ts_str:
        return None
    try:
        if ts_str.isdigit():
            val = int(ts_str)
            if val > 10**17: 
                secs = val / 10000000 - 11644473600
                dt = datetime.fromtimestamp(secs, tz=timezone.utc)
            elif val > 10**12: 
                dt = datetime.fromtimestamp(val / 1000, tz=timezone.utc)
            else: 
                dt = datetime.fromtimestamp(val, tz=timezone.utc)
            return dt
        return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
    except Exception:
        return None

ICON_MAP = {
    'web_site': '1', 'email': '19', 'key': '0', 'credit_card': '66',
    'bank': '3', 'insurance': '48', 'membership': '48', 'id': '9',
    'router': '3', 'network': '3', 'lock': '52', 'social_security': '9', 'cd': '17',
}

def get_domain(url):
    try:
        if not url: return "site"
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed = urlparse(url)
        hostname = parsed.netloc
        if hostname.startswith('www.'):
            hostname = hostname[4:]
        parts = hostname.split('.')
        if len(parts) > 1:
            return parts[-2]
        return hostname if hostname else "site"
    except Exception:
        return "site"

def get_split_prefix(url):
    try:
        if not url: return "site"
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed = urlparse(url)
        hostname = parsed.netloc
        
        if hostname.startswith('www.'):
            hostname = hostname[4:]
            
        parts = hostname.split('.')
        
        if len(parts) >= 3:
            return parts[0] # Return subdomain
        
        if len(parts) == 2:
            return parts[0] # Return domain
        
        return hostname if hostname else "site"
    except Exception:
        return "site"

def convert_sic_to_kpx(sic_xml_bytes, output_file, kp_password, keyfile=None):

    print("[*] Parsing XML data...")
    try:
        doc = xmltodict.parse(sic_xml_bytes, process_namespaces=True)
    except Exception as e:
        print(f"Error parsing decrypted XML: {e}")
        sys.exit(1)

    if not doc:
        print("Error: XML parsed to empty dictionary.")
        sys.exit(1)

    root_key = next(iter(doc))
    db = doc[root_key]
    
    print(f"[*] Found root element '<{root_key}>'")

    # Ensure KDBX Extension
    if output_file.lower().endswith('.kdb'):
        output_file = output_file[:-4] + '.kdbx'
        print(f"[!] Output extension changed to .kdbx: {output_file}")
    elif not output_file.lower().endswith('.kdbx'):
        output_file += '.kdbx'

    print(f"[*] Creating KeePass database: {output_file}")
    kp = pykeepass.create_database(output_file, password=kp_password, keyfile=keyfile)
    
    # 1. Process Labels -> Groups
    label_id_map = {"Root": kp.root_group}
    group_name_map = {"Root": kp.root_group} 
    
    labels = safe_get(db, 'label', default=[])
    if not isinstance(labels, list):
        labels = [labels] if labels else []

    for lbl in labels:
        name = safe_get(lbl, '@name')
        lbl_id = safe_get(lbl, '@id')
        if name and lbl_id:
            g = kp.add_group(kp.root_group, name)
            label_id_map[lbl_id] = g
            group_name_map[name] = g

    # 2. Process Cards -> Entries
    cards = safe_get(db, 'card', default=[])
    if not isinstance(cards, list):
        cards = [cards] if cards else []

    print(f"[*] Processing {len(cards)} card definitions...")

    count_processed = 0
    for card in cards:
        # Skip Templates and Deleted
        if safe_get(card, '@template') == 'true' or safe_get(card, '@deleted') == 'true':
            continue

        count_processed += 1
        
        title = safe_get(card, '@title', 'Untitled')
        
        # -----------------------------------------------------------
        # 1. PARSE FIELDS EARLY (To get Email for Group Logic)
        # -----------------------------------------------------------
        fields = safe_get(card, 'field')
        if not isinstance(fields, list):
            fields = [fields] if fields else []

        all_items = []
        
        # We need to find the main login/email specifically for group matching
        found_email_for_group = "" 
        
        for idx, field in enumerate(fields):
            if not field: continue
            
            f_type = safe_get(field, '@type', '').lower()
            f_name = safe_get(field, '@name', 'Unknown')
            f_val = safe_get(field, '#text') or safe_get(field, '@value')
            if f_val is None: f_val = ""
            
            logical_type = 'custom'
            
            if f_type in ['username', 'login', 'email'] or f_name.lower() in ['username', 'user', 'email', 'login']:
                logical_type = 'login'
                # Grab first login/email found for group matching
                if not found_email_for_group and f_val:
                    found_email_for_group = f_val
                    
            elif f_type == 'password' or f_name.lower() in ['password', 'pass', 'pin']:
                logical_type = 'password'
            elif f_type in ['url', 'website'] or f_name.lower() in ['url', 'website', 'link']:
                logical_type = 'url'
            elif f_type == 'notes':
                logical_type = 'notes'
            
            all_items.append({
                'idx': idx,
                'name': f_name,
                'val': f_val,
                'type': logical_type
            })

        # -----------------------------------------------------------
        # 2. DETERMINE GROUP (Using Title + Email)
        # -----------------------------------------------------------
        
        target_group = None
        
        # Construct search text: Title + Space + Email
        # Normalized to lowercase for case-insensitive matching
        search_text = f"{title} {found_email_for_group}".lower()
        
        for group_name, keywords in GROUP_RULES.items():
            match_found = False
            for kw in keywords:
                # Check if keyword exists in either title or email
                if kw.lower() in search_text:
                    match_found = True
                    break
            
            if match_found:
                if group_name not in group_name_map:
                    print(f"    [+] Creating Rule Group: '{group_name}'")
                    g = kp.add_group(kp.root_group, group_name)
                    group_name_map[group_name] = g
                
                target_group = group_name_map[group_name]
                break

        # Fallback to Label ID if no keyword matched
        if target_group is None:
            target_group = kp.root_group
            label_ref = safe_get(card, 'label_id')
            if label_ref:
                if isinstance(label_ref, list):
                    label_ref = label_ref[0]
                if label_ref in label_id_map:
                    target_group = label_id_map[label_ref]

        # -----------------------------------------------------------
        # 3. PROCESSING LOGIC
        # -----------------------------------------------------------
        
        logins = [x for x in all_items if x['type'] == 'login' and x['val']]
        urls = [x for x in all_items if x['type'] == 'url' and x['val']]
        passes = [x for x in all_items if x['type'] == 'password' and x['val']]
        
        url_count = len(urls)
        pass_count = len(passes)
        
        main_login_obj = logins[0] if logins else None
        main_login_val = main_login_obj['val'] if main_login_obj else ""
        
        is_email_login = False
        email_domain = ""
        
        if main_login_val and '@' in main_login_val:
            is_email_login = True
            try:
                email_domain = main_login_val.split('@')[1]
            except:
                email_domain = ""

        # SPLIT CONDITION
        do_split = False
        if url_count > 2 and pass_count >= url_count:
            do_split = True

        icon_id = '0'
        symbol = safe_get(card, '@symbol')
        if symbol and symbol in ICON_MAP:
            icon_id = ICON_MAP[symbol]
            
        notes = safe_get(card, 'notes', default="")

        # Helper
        def add_custom_exact(entry, key, val, protect=False):
            final_key = key
            if final_key in entry.custom_properties:
                count = 2
                while f"{final_key} ({count})" in entry.custom_properties:
                    count += 1
                final_key = f"{final_key} ({count})"
            try:
                entry.set_custom_property(final_key, str(val), protect=protect)
            except Exception: pass

        # --- CASE A: SPLIT MODE ---
        if do_split:
            print(f"    [+] Splitting '{title}' ({url_count} URLs)")
            
            main_url_val = ""
            main_pass_val = ""
            used_indices = set()
            
            if main_login_obj:
                used_indices.add(main_login_obj['idx'])
            
            if is_email_login:
                main_url_val = f"https://{email_domain}" if email_domain else ""
                if passes:
                    main_pass_val = passes[0]['val']
                    used_indices.add(passes[0]['idx'])
            else:
                if urls:
                    main_url_val = urls[0]['val']
                    used_indices.add(urls[0]['idx'])
                if passes:
                    main_pass_val = passes[0]['val']
                    used_indices.add(passes[0]['idx'])

            final_main_title = title
            dups = kp.find_entries(title=final_main_title, group=target_group)
            if dups:
                c = 1
                while kp.find_entries(title=f"{final_main_title} ({c})", group=target_group): c += 1
                final_main_title = f"{final_main_title} ({c})"

            entry = kp.add_entry(target_group, final_main_title, main_login_val, main_pass_val, url=main_url_val, notes=notes, icon=icon_id)
            
            split_indices = set()
            if is_email_login:
                for u in urls: split_indices.add(u['idx'])
                for i in range(1, len(passes)): split_indices.add(passes[i]['idx'])
            else:
                for i in range(1, len(urls)): split_indices.add(urls[i]['idx'])
                for i in range(1, len(passes)): split_indices.add(passes[i]['idx'])
                
            for item in all_items:
                if item['idx'] in used_indices: continue
                if item['idx'] in split_indices: continue
                protect = 'pass' in item['name'].lower() or 'pin' in item['name'].lower()
                add_custom_exact(entry, item['name'], item['val'], protect=protect)

            # Create Split Entries
            if is_email_login:
                for i, url_obj in enumerate(urls):
                    pass_idx = i + 1
                    if pass_idx < len(passes):
                        split_pass_obj = passes[pass_idx]
                        split_url = url_obj['val']
                        split_pass = split_pass_obj['val']
                        
                        prefix = get_split_prefix(split_url)
                        split_title = f"{prefix} - {title}"
                        
                        dups = kp.find_entries(title=split_title, group=target_group)
                        final_split_title = split_title
                        if dups:
                            c = 1
                            while kp.find_entries(title=f"{split_title} ({c})", group=target_group): c += 1
                            final_split_title = f"{split_title} ({c})"
                        
                        print(f"        -> Adding Split Entry: '{final_split_title}'")
                        
                        split_entry = kp.add_entry(target_group, final_split_title, main_login_val, split_pass, url=split_url, icon=icon_id)
                        
                        for item in all_items:
                            if item['idx'] in used_indices: continue
                            if item['idx'] == url_obj['idx'] or item['idx'] == split_pass_obj['idx']: continue
                            protect = 'pass' in item['name'].lower()
                            add_custom_exact(split_entry, item['name'], item['val'], protect=protect)
                        
                        mod_time = parse_timestamp(safe_get(card, '@time_stamp'))
                        created_time = parse_timestamp(safe_get(card, '@first_stamp'))
                        if mod_time: split_entry.mtime = mod_time
                        if created_time: split_entry.ctime = created_time

            else:
                for i in range(1, url_count):
                    url_obj = urls[i]
                    if i < len(passes):
                        pass_obj = passes[i]
                        split_url = url_obj['val']
                        split_pass = pass_obj['val']
                        
                        prefix = get_split_prefix(split_url)
                        split_title = f"{prefix} - {title}"
                        
                        dups = kp.find_entries(title=split_title, group=target_group)
                        final_split_title = split_title
                        if dups:
                            c = 1
                            while kp.find_entries(title=f"{split_title} ({c})", group=target_group): c += 1
                            final_split_title = f"{split_title} ({c})"
                        
                        print(f"        -> Adding Split Entry: '{final_split_title}'")
                        
                        split_entry = kp.add_entry(target_group, final_split_title, main_login_val, split_pass, url=split_url, icon=icon_id)
                        
                        for item in all_items:
                            if item['idx'] in used_indices: continue
                            if item['idx'] == url_obj['idx'] or item['idx'] == pass_obj['idx']: continue
                            protect = 'pass' in item['name'].lower()
                            add_custom_exact(split_entry, item['name'], item['val'], protect=protect)
                        
                        mod_time = parse_timestamp(safe_get(card, '@time_stamp'))
                        created_time = parse_timestamp(safe_get(card, '@first_stamp'))
                        if mod_time: split_entry.mtime = mod_time
                        if created_time: split_entry.ctime = created_time

        # --- CASE B: SINGLE ENTRY MODE ---
        else:
            print(f"    [+] Adding Entry: '{title}'")
            
            used_indices = set()
            
            if main_login_obj:
                main_login_val = main_login_obj['val']
                used_indices.add(main_login_obj['idx'])
            
            main_pass_val = ""
            if passes:
                main_pass_val = passes[0]['val']
                used_indices.add(passes[0]['idx'])
            
            main_url_val = ""
            if is_email_login:
                main_url_val = f"https://{email_domain}" if email_domain else ""
            else:
                if urls:
                    main_url_val = urls[0]['val']
                    used_indices.add(urls[0]['idx'])
            
            final_main_title = title
            dups = kp.find_entries(title=final_main_title, group=target_group)
            if dups:
                c = 1
                while kp.find_entries(title=f"{final_main_title} ({c})", group=target_group): c += 1
                final_main_title = f"{final_main_title} ({c})"

            entry = kp.add_entry(target_group, final_main_title, main_login_val, main_pass_val, url=main_url_val, notes=notes, icon=icon_id)
            
            for item in all_items:
                if item['idx'] in used_indices: continue
                if item['type'] == 'notes' and not item['val']: continue
                protect = item['type'] == 'password' or 'pass' in item['name'].lower() or 'pin' in item['name'].lower() or 'secret' in item['name'].lower()
                add_custom_exact(entry, item['name'], item['val'], protect=protect)

        # Attachments
        attachments = safe_get(card, 'attachment', default=[])
        if not isinstance(attachments, list):
            attachments = [attachments] if attachments else []
        for att in attachments:
            att_name = safe_get(att, '@name', 'unnamed_file')
            b64_data = safe_get(att, '#text')
            if b64_data:
                try:
                    binary_data = base64.b64decode(b64_data)
                    binary_id = kp.add_binary(binary_data)
                    entry.add_attachment(binary_id, att_name)
                except Exception: pass

        mod_time = parse_timestamp(safe_get(card, '@time_stamp'))
        created_time = parse_timestamp(safe_get(card, '@first_stamp'))
        if mod_time: entry.mtime = mod_time
        if created_time: entry.ctime = created_time

    print("[*] Saving database...")
    kp.save()
    print(f"[+] Success! Processed {count_processed} source cards.")
    print(f"[+] Database saved to {output_file}")

# --------------------------------------------------------------------------------
# Main Entry Point
# --------------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="SafeInCloud to KeePassXC Converter")
    parser.add_argument("input_file", help="Path to the SafeInCloud .db file")
    parser.add_argument("output_file", help="Path for the new KeePass .kdbx file")
    parser.add_argument("-k", "--keyfile", help="Optional keyfile for the output KeePass database", default=None)
    
    args = parser.parse_args()

    sic_pass = getpass.getpass("Enter SafeInCloud Master Password: ")
    
    while True:
        kp_pass = getpass.getpass("Enter New Password for KeePass DB: ")
        kp_pass_confirm = getpass.getpass("Confirm New Password for KeePass DB: ")
        if kp_pass == kp_pass_confirm:
            break
        print("Passwords do not match. Please try again.")

    print(f"[*] Decrypting {args.input_file}...")
    try:
        decryptor = SafeInCloudDecryptor(args.input_file, sic_pass)
        xml_data = decryptor.decrypt()
    except Exception as e:
        print(f"ERROR: Failed to decrypt file. Check password. ({e})")
        sys.exit(1)

    convert_sic_to_kpx(xml_data, args.output_file, kp_pass, args.keyfile)

if __name__ == "__main__":
    main()