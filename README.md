# IOC-Extractor
A Command-line tool to extract indicators of compromise from various sources and export to various formats.

💡 Use IOC-Extractor to...
- Extract IOCs from batches of threat reports
- Generate a IOC section for reports-in-progress
- Quickly share IOCs exported to STIX and JSON
- Feed IOCs from the latest reports into threat data feeds, firewalls, IDS/IPS, etc
- (use the extractor_class.py class file to) write your own scripts!

📚 IOC Extractor...
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
1. Clone the repository and navigate inside it.
```
git clone https://github.com/Red91K/IOC-Extractor.git
cd IOC-Extractor
```
2. Create two directories titled `Extracted` and `Sources` respectively.
```
mkdir Extracted
mkdir Sources
```


# Running the Tool
```
python3 Extractor.py  
```
- Follow the directions displayed by the script:
  - First import sources either from a URL or a file within the Sources directory. Give each source a descriptive name.
  - Wait for the script to finish extracting the IOCs
  - Choose an export method! Extractor currently supports plain text, markdown, json, and STIX 2.1
  - Get your extracted IOCs! Exported IOCs can be found as files in the `Extracted` directory, and will also be automatically copied to clipboard and displayed by the script. 
- You can customise things like detection sensitivity, types of IOCs to search for, and whether or not to fang exported indicators by editing the config.json file.
