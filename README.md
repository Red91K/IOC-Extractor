# IOC-Extractor
Command-line tool to extract indicators of compromise from various sources and export to various formats.

- input sources: local plain text file OR website
- output sources: JSON, Plain text, Markdown
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
mkdir Extracted
mkdir Sources
```

# Running the Tool
```
python3 Extractor.py  
```
