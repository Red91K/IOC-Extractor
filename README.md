# IOC-Extractor
Command-line tool to extract indicators of compromise from various sources and export to various formats.

- Supports two sources: plain-text file OR website
- Multiple export formats: JSON, Plain text, Markdown
- Extracted Indicators:
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
