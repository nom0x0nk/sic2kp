# sic2kp

**SafeInCloud DB → KeePass/KeePassXC DB without losing any custom fields**

Convert SafeInCloud DB files to KeePass/KeePassXC compatible `.kdbx` format with **automatic category detection** and **complete data preservation**.

---

## Features

### Core Features
- ✅ **Secure Decryption** - Safely decrypt SafeInCloud databases using AES-256 and PBKDF2 key derivation
- ✅ **Format Conversion** - Convert to KeePass/KeePassXC compatible `.kdbx` format
- ✅ **Cross-Platform** - Windows, Linux, and macOS support
- ✅ **Python 3.10+** - Modern Python support (tested with 3.14)

### Data Handling
- ✅ **Full Data Preservation** - All fields, custom attributes, and metadata are preserved
- ✅ **Timestamp Preservation** - Original creation and modification dates are maintained
- ✅ **Attachment Support** - Binary attachments are converted and stored in KeePass
- ✅ **Custom Fields** - All custom field types are preserved with automatic protection for sensitive data
- ✅ **Multi-Password Entries** - Intelligently handles entries with multiple URLs and passwords by splitting them into separate entries

### Smart Organization
- ✅ **Automatic Categorization** - Keywords-based automatic grouping into 6 categories (Finance, Social, Shopping, Gaming, Work, Email)
- ✅ **Original Group Structure** - Preserves your existing SafeInCloud labels/groups
- ✅ **Duplicate Handling** - Automatically resolves duplicate entry names with numbered suffixes
- ✅ **Icon Mapping** - Maps field types to appropriate KeePass icons:
  - 🌐 Website/URL fields
  - 📧 Email addresses
  - 💳 Credit cards
  - 🏦 Bank accounts
  - 🔐 Passwords and security keys
  - 📄 Membership/ID fields

### Security Features
- ✅ **Protected Fields** - Password fields automatically marked as protected in KeePass
- ✅ **Optional Keyfile** - Support for additional keyfile-based protection
- ✅ **Password Confirmation** - Confirmation prompt when setting new KeePass password
- ✅ **Secure Extraction** - No temporary files; data stays in memory during processing

## Requirements

- **Python Version**: 3.10+ (tested with 3.14)
- **Operating Systems**: Windows, Linux, macOS

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/nom0x0nk/sic2kp.git
cd sic2kp
```

### 2. Create a Virtual Environment

#### **Windows (Command Prompt)**

```cmd
python -m venv venv
venv\Scripts\activate.bat
```

#### **Windows (PowerShell)**

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```

#### **Ubuntu/Linux Mint/Debian-based**

```bash
sudo apt-get update
sudo apt-get install python3 python3-venv
python3 -m venv venv
source venv/bin/activate
```

#### **Arch/Cachy/Arch-based (Bash/Zsh)**

```bash
sudo pacman -Syu
sudo pacman -S python
python -m venv venv
source venv/bin/activate
```

#### **Arch/Cachy/Arch-based (Fish Shell)**

```fish
sudo pacman -Syu
sudo pacman -S python
python -m venv venv
source venv/bin/activate.fish
```

### 3. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

Or install packages directly:

```bash
pip install pycryptodomex xmltodict passlib pykeepass
```

## Required Packages

| Package | Version | Purpose |
|---------|---------|---------|
| `pycryptodomex` | Latest | Cryptography for decryption |
| `xmltodict` | Latest | XML parsing |
| `passlib` | Latest | Password hashing utilities |
| `pykeepass` | Latest | KeePass database handling |

## Usage

### Basic Conversion

```bash
python main.py safeincloud.db output.kdbx
```

You will be prompted for:
1. **SafeInCloud Master Password** - Your original SafeInCloud database password
2. **New KeePass Password** - Password for the new KeePass database (with confirmation)

### With Keyfile Protection

Protect your KeePass database with both a password and keyfile:

```bash
python main.py safeincloud.db output.kdbx --keyfile /path/to/keyfile.key
```

### View All Options

```bash
python main.py --help
```

## Automatic Category Organization

The tool intelligently categorizes entries based on **GROUP_RULES** keyword matching:

> 💡 **Tip**: You can customize these categories! Edit the `GROUP_RULES` dictionary at the top of [main.py](main.py#L25) to add your own categories and keywords.

| Group | Keywords | Use Case |
|-------|----------|----------|
| **Finance** | bank, insurance, tax, finance, paypal | Banking and financial accounts |
| **Social** | facebook, twitter, instagram, linkedin, tiktok | Social media accounts |
| **Shopping** | amazon, ebay, aliexpress, shop, store | E-commerce and shopping sites |
| **Gaming** | steam, epic, origin, uplay, battle.net, blizzard | Gaming platforms |
| **Work** | office, slack, zoom, teams, work | Work and productivity tools |
| **Email** | gmail, outlook, webmail, mail | Email accounts |

**How it Works**: 
- Each entry's **Title** and **Email/Login** fields are scanned for keyword matches (case-insensitive)
- The first matching category determines the entry's group
- Entries that don't match any rule stay in their original SafeInCloud group
- Groups are automatically created if needed

### Entry Processing Examples

#### Single Entry (Standard)
```
SafeInCloud: "Facebook Account" (facebook@example.com)
  ↓ Converted with 1 URL + 1 Password
KeePass Group: Social → "Facebook Account"
```

#### Multiple URLs/Passwords (Split)
```
SafeInCloud: "Work VPN" 
  - URL 1: vpn1.company.com (password1)
  - URL 2: vpn2.company.com (password2)
  ↓ Intelligently split into multiple entries
KeePass Group: Work
  ├── "Work VPN"
  ├── "vpn1 - Work VPN"
  └── "vpn2 - Work VPN"
```

#### Email Login (Domain Extraction)
```
SafeInCloud: "Cloud Service" (user@example.com)
  ↓ Domain automatically extracted
KeePass: Entry with URL "https://example.com"
```

## Advanced Features

### Custom Field Mapping

All SafeInCloud field types are mapped appropriately:
- **Standard fields**: Username, password, URL, notes → Native KeePass fields
- **Custom fields**: Preserved as KeePass custom attributes
- **Sensitive data**: Fields containing "password", "pin", or "secret" are marked protected

### Attachment Handling

Binary attachments from SafeInCloud are:
- Decoded from base64 format
- Stored as KeePass binary attachments
- Linked to the corresponding entry

### Duplicate Prevention

If multiple entries have the same title:
```
Entry name: "Gmail (1)", "Gmail (2)", etc.
```

## Project Structure

```
sic2kp/
├── main.py           # Main conversion script
├── requirements.txt  # Python dependencies
├── README.md         # This file
└── .gitignore        # Git ignore rules
```

## Troubleshooting

### Decryption Issues

**"Failed to decrypt file. Check password."**
- Verify your SafeInCloud master password is correct
- Ensure the `.db` file is a valid SafeInCloud database
- Try reopening your SafeInCloud app to ensure the database isn't corrupted

### Virtual Environment Issues

- **Linux/macOS**: If `venv` command fails, install with: `sudo apt-get install python3-venv` (Debian) or `brew install python3` (macOS)
- **Windows**: Ensure Python is in your system PATH; reinstall Python with "Add Python to PATH" option checked

### Package Installation Issues

```bash
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt --no-cache-dir
```

If specific packages fail:
```bash
pip install pycryptodomex xmltodict passlib pykeepass --force-reinstall
```

### Permission Denied (Linux/macOS)

```bash
chmod +x main.py
python main.py safeincloud.db output.kdbx
```

### Import Errors

Ensure all dependencies are properly installed:
```bash
pip list | grep -E "pycryptodomex|xmltodict|passlib|pykeepass"
```

If any are missing:
```bash
pip install -r requirements.txt
```

### Output File Issues

- The tool automatically converts `.kdb` to `.kdbx` format
- If no extension is provided, `.kdbx` is automatically added
- Ensure you have write permissions in the output directory

## What Happens During Conversion

1. **Decryption** - SafeInCloud database is decrypted using AES-256-CBC with PBKDF2 derivation
2. **Parsing** - XML structure is parsed to extract all cards (entries) and labels (groups)
3. **Classification** - Each entry is categorized using keyword matching
4. **Group Creation** - Original groups and automatic category groups are created in KeePass
5. **Entry Processing**:
   - Data is extracted from SafeInCloud fields
   - Multiple URLs/passwords are intelligently split into separate entries if needed
   - Icons are assigned based on field types
   - Custom fields are preserved with protection for sensitive data
   - Timestamps are migrated
   - Attachments are converted
6. **Saving** - Final KeePass database is saved with your specified password

## Safety & Security Notes

⚠️ **Important**:
- Your original SafeInCloud password is **never saved or stored** - it's only used to decrypt
- The new KeePass password is **only set when you create the database** - you set it yourself
- All processing happens **in memory** - no temporary unencrypted files are created
- Original SafeInCloud file remains **untouched**
- Perform this conversion on a **trusted, secure computer**
- Keep backup copies of both your SafeInCloud and KeePass databases

## Customization

### Modifying Categorization Rules

To customize how entries are categorized, edit the `GROUP_RULES` dictionary in [main.py](main.py):

```python
GROUP_RULES = {
    "Finance": ["bank", "insurance", "tax", "finance", "paypal"],
    "Social": ["facebook", "twitter", "instagram", "linkedin", "tiktok"],
    "Shopping": ["amazon", "ebay", "aliexpress", "shop", "store"],
    "Gaming": ["steam", "epic", "origin", "uplay", "battle.net", "blizzard"],
    "Work": ["office", "slack", "zoom", "teams", "work"],
    "Email": ["gmail", "outlook", "webmail", "mail"]
}
```

Add or modify categories and keywords as needed. Keywords are case-insensitive.

## FAQ

**Q: Can I reverse the conversion and go back to SafeInCloud?**
A: No, this tool is one-way only. Conversion to KeePass is permanent. Always keep a backup of your original SafeInCloud file.

**Q: Will my folder structure be preserved?**
A: Yes! Your original SafeInCloud labels/groups are preserved as KeePass groups. Automatic categories are created additionally based on keyword rules.

**Q: What if SafeInCloud has duplicate entry titles?**
A: The tool automatically appends `(1)`, `(2)`, etc. to resolve duplicates.

**Q: Can I use the same password for both SafeInCloud and KeePass?**
A: Yes, you can, but it's recommended to use a different, strong password for KeePass.

**Q: What file formats does this support?**
A: Input: SafeInCloud `.db` files only. Output: `.kdbx` format (KeePass 2.x and KeePassXC compatible).

**Q: Is this tool official?**
A: No, this is a community tool. It's not affiliated with SafeInCloud or KeePass/KeePassXC projects.

**Q: What happens to empty fields or notes?**
A: All non-empty fields are preserved. Empty fields and blank notes are discarded to keep the database clean.

**Q: Can I convert multiple SafeInCloud databases?**
A: Yes, run the tool multiple times with different input/output files, or merge KeePass databases manually using KeePass.

## Contributing

Contributions are welcome! Please open an issue or pull request.

---

**Note**: Always keep your passwords and sensitive data secure. This tool handles encrypted databases carefully and respects your privacy.
