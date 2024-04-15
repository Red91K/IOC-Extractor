# IOC-Extractor
A Command-line tool to extract indicators of compromise from various sources and export to various formats.

💡 Use IOC-Extractor to...
- Extract IOCs from batches of threat reports
- Generate a IOC section for reports-in-progress
- Quickly share IOCs exported to STIX and JSON
- Feed IOCs from the latest reports into threat data feeds, firewalls, IDS/IPS, etc
- (use the extractor_class.py class file to) write your own scripts!

IOC Extractor...
- Supports two sources: plain-text file OR website
- Features multiple export formats: JSON, Plain text, Markdown
- Detects the following Indicators Of Compromise:
  - IPv4 & v6 Addresses
  - Domains
  - URLs
  - MD5, SHA-1, SHA-256, SHA-512 File Hashes
  - JARM Hashes
  - Email Addresses
  - CVEs
  - MITRE ATTACK IDs

# Getting Started
```
git clone https://github.com/Red91K/IOC-Extractor.git
cd IOC-Extractor
mkdir Extracted
mkdir Sources
```

# Running the Tool
```
python3 Extractor.py  
```
- Outputted files can be found in the `Extracted` directory
- Extracted IOCs are automatically copied to clipboard
- You can customise things like detection sensitivity, types of IOCs to search for, and whether or not to fang exported indicators by editing the config.json file.
