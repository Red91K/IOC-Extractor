## python Script to extract indicators of compromise from various file formats & from the clipboard
# option for multiple files
# print to cli, copy to clipboard, export to 
## .json, STIXX, .txt
# indicator types
# ipv4, ipv6, domains, urls, email addresses, md5 & sha file hashes

import os
import re
import subprocess
import json
from datetime import datetime, timezone
import urllib.request
from html.parser import HTMLParser
import random, string


class IOC_GROUP:
   SETTINGS = {}
   # all possible indicators of compromise
   # if copying pasting an entire website, can pick up vendor urls & domains, internal ip addresses passed as cli arguments, etc
   # NOT RECCOMENDED
   LOW_FIDELITY_IOC_REGEX = {
      # any technically valid ip address, even if witin reserved blocks
      # includes defanged ip addresses
      "IPv4 Addresses": r"((\d{1,3})(\[\.\]|\.)){3}(\d{1,3})",

      # any technically valid ipv6 address, including most abreviations
      # includes defanged ip addresses
      "IPv6 Addresses": r"(([0-9a-fA-F]{0,4}:)|([0-9a-fA-F]{0,4}\[\:\])){3,7}[0-9a-fA-F]{1,4}\b",

      # includes defanged domains
      # will include domains found in urls, minus the scheme & path
      "Domains":r"\b[a-zA-Z0-9.-]+(\[\.\])?[a-zA-Z0-9.-]+(\.|\[\.\])[a-z]{2,}\b",
      # includes defanged urls
      # must include //
      "URLs":
         r"[a-zA-Z:]{1,256}\/\/[-a-zA-Z0-9@:%._\[\]\+~#=\/]{1,256}(\.|\[\.\])[a-z]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&\/\/=]*)",

      "Email Addresses": # TODO - ARE EMAILS ALSO DEFANGED?
         r"(?:[a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_`{|}~-]+)*|\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])",
      # matches based on hash length
      "MD5 Hashes":
         r"\b[a-fA-F0-9]{32}\b",
      "SHA-1 Hashes":
         r"\b[a-fA-F0-9]{40}\b",
      "SHA256 Hashes":
         r"\b[a-fA-F0-9]{64}\b",
      "SHA512 Hashes":
         r"\b[a-fA-F0-9]{128}\b",
      "JARM Hashes":
         r"\b[a-fA-F0-9]{62}\b",
      "CVEs": r"\b(CVE-\d{4}-\d{4})\b",
      "MITRE ATTACK IDs": r"\b(T\d{4}(\.\d{3})?)\b"
   }

   HIGH_FIDELITY_IOC_REGEX = {
      # any technically valid, DEFANGED ip address
      "IPv4 Addresses": r"(?=[^\s]*\[\.\])((\d{1,3})(\[\.\]|\.)){3}(\d{1,3})",

      # any technically valid, DEFANGED ipv6 address, including most abreviations
      "IPv6 Addresses": r"(?=[^\s]*\[\:\])(([0-9a-fA-F]{0,4}:)|([0-9a-fA-F]{0,4}\[\:\])){3,7}[0-9a-fA-F]{1,4}",

      # MUST BE A DEFANGED DOMAIN
      # will NOT include domains found in urls
      # there needs to be a line break or a space or a , or a . on both ends
      # will not include the scheme & path
      "Domains": r"(^|\s)(?=[^\s]*\[\.\])[a-zA-Z0-9.-]+(\[\.\])?[a-zA-Z0-9.-]+(\.|\[\.\])[a-z]{2,}(?=^|\s|,|.)",
      
      # URL MUST BE DEFANGED
      # must include //
      "URLs": r"(?=[^\s]*\[\.\])[a-zA-Z:]{1,256}\/\/[-a-zA-Z0-9@:%._\[\]\+~#=\/]{1,256}(\.|\[\.\])[a-z]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&\/\/=]*)",

      "Email Addresses":
         r"(?:[a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_`{|}~-]+)*|\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])",
      # matches based on hash length
      "MD5 Hashes":
         r"\b[a-fA-F0-9]{32}\b",
      "SHA-1 Hashes":
         r"\b[a-fA-F0-9]{40}\b",
      "SHA256 Hashes":
         r"\b[a-fA-F0-9]{64}\b",
      "SHA512 Hashes":
         r"\b[a-fA-F0-9]{128}\b",
      "JARM Hashes":
         r"\b[a-fA-F0-9]{62}\b",
      "CVEs": r"\b(CVE-\d{4}-\d{4})\b",
      "MITRE ATTACK IDs": r"\b(T\d{4}(\.\d{3})?)\b"
   }


   def __init__(self, ioc_rules:dict[str,str] = HIGH_FIDELITY_IOC_REGEX, sources:dict[str:str] = {}, ioc_dict:dict[str,str] = {}):
      try:
         if not self.SETTINGS["High-Fidelity-Ruleset"]:
            ioc_rules = dict(self.LOW_FIDELITY_IOC_REGEX) # needed because pass by reference
      except:
         pass

      try:
         for rule_name, value in self.SETTINGS["Search-Options"].items():
            if not value:
               del(ioc_rules[rule_name])
      except Exception as e:
         pass

      self.ioc_rules = ioc_rules
      self.sources = sources
      self.ioc_dict = ioc_dict
   
   @classmethod
   def load_settings(cls):
      with open("config.json","r") as f:
         cls.SETTINGS = json.load(f)

   def load_source(self, source_str:str, source_name:str):
      filepath = False
      url = False
      if os.path.isfile(source_str):
         filepath = source_str
      elif os.path.isfile(os.path.join("Sources", source_str)):
         filepath = os.path.join("Sources", source_str)
      else:
         url = source_str

      if filepath:
         with open(filepath, "r") as f:
            self.sources[source_name] = f.read()
         print(f"\nSOURCE [{source_name}] successfully loaded from URL!")
      else:
         try:
            title, text = TextExtractor.extract_info_from_website(url)
         except:
            print("INVALID URL OR FILEPATH")
            return
         
         if not text:
            print("INVALID URL OR FILEPATH")
            return
         
         self.sources[source_name] = text
         print(f"\nSOURCE [{source_name}] successfully loaded from URL!")


   def extract_iocs(self) -> dict[str,str]:
      for source_name, text in self.sources.items():
         print(f"[EXTRACTING FROM SOURCE {source_name}...]")
         if source_name not in self.ioc_dict.keys():
            self.ioc_dict[source_name] = {}
         for key, value in self.ioc_rules.items():
            results = re.finditer(value, text)
            if key not in self.ioc_dict[source_name].keys():
               self.ioc_dict[source_name][key] = set()
            
            print(f"\nSEARCHING for [{key}]...")
            for i in results:
               matched = i.group().strip()
               self.ioc_dict[source_name][key].add(self.fang(matched))
               print(f"[MATCH FOUND - {self.fang(matched)}]")
         
      print("[IOC EXTRACTION FINISHED!]")


   # group by indicator type
   def just_indicators(self, group_by_source:bool):
      if group_by_source:
         out_str = ""
         for source_name, cur_ioc_dict in self.ioc_dict.items():
            out_str += f"Source [{source_name}]"
            for key in cur_ioc_dict:
               if cur_ioc_dict[key]:
                  out_str += "\n\n"
               else:
                  continue
               for indicator in cur_ioc_dict[key]:
                  out_str += f"{indicator}\n"
            out_str += "\n\n" 
      else:
         out_str = ""
         combined_dict = {}
         for source_name, cur_ioc_dict in self.ioc_dict.items():
            for key in cur_ioc_dict:
               if key not in combined_dict.keys():
                  combined_dict[key] = set()
               for indicator in cur_ioc_dict[key]:
                  combined_dict[key].add(indicator)

         for key in combined_dict:
            if cur_ioc_dict[key]:
               pass
            else:
               continue
            for indicator in cur_ioc_dict[key]:
               out_str += f"{indicator}\n"
            out_str += "\n\n"
      
      return out_str


   # to md. Backticks & everything
   def pretty_indicators(self, group_by_source:bool):
      if group_by_source:
         out_str = ""
         for source_name, cur_ioc_dict in self.ioc_dict.items():
            out_str += f"# Source [{source_name}]"
            for key in cur_ioc_dict:
               if cur_ioc_dict[key]:
                  out_str += "\n\n"
                  out_str += f"## {key}\n"
               else:
                  continue
               for indicator in cur_ioc_dict[key]:
                  out_str += f"`{indicator}`\n"
            out_str += "\n\n" 
      else:
         out_str = ""
         combined_dict = {}
         for source_name, cur_ioc_dict in self.ioc_dict.items():
            for key in cur_ioc_dict:
               if key not in combined_dict.keys():
                  combined_dict[key] = set()
               for indicator in cur_ioc_dict[key]:
                  combined_dict[key].add(indicator)


         for key in combined_dict:
            if cur_ioc_dict[key]:
               out_str += f"# {key}\n"
            else:
               continue
            for indicator in cur_ioc_dict[key]:
               out_str += f"`{indicator}`\n"
            out_str += "\n\n"
      
      return out_str
   

   @classmethod
   def random_alphanumeric(cls, len:int) -> str:
      return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(len))
   
   @classmethod
   def generate_stix_id(cls,type:str) -> str:
      # format: indicator--031778a4-057f-48e6-9db9-c8d72b81ccd5
      return f"{type}--{cls.random_alphanumeric(8)}-{cls.random_alphanumeric(4)}-{cls.random_alphanumeric(4)}-{cls.random_alphanumeric(12)}"
   
   @classmethod
   def current_time(cls):
      current_utc_time = datetime.now(timezone.utc)
      return current_utc_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
   
   @classmethod
   def fang(cls, indicator:str):
      try:
         if cls.SETTINGS["Fang-Indicators"]:
            return indicator.replace("[.]",".")
         else:
            return indicator
      except:
         print("ERRORADSF")
         return indicator.replace("[.]",".")

   def generate_stix(self, indicator:str, indicator_type:str):
      STIX_MAPPINGS = {
         "IPv4 Addresses": {
            "type": "indicator",
            "id": self.generate_stix_id("indicator"),
            "pattern":f"[ipv4-addr:value = '{indicator}']"
         },
         "IPv6 Addresses": {
            "type": "indicator",
            "id": self.generate_stix_id("indicator"),
            "pattern":f"[ipv6-addr:value = '{indicator}']"
         },
         "Domains": {
            "type": "indicator",
            "id": self.generate_stix_id("indicator"),
            "pattern":f"[domain-name:value = '{indicator}']"
         },
         "URLs": {
            "type": "indicator",
            "id": self.generate_stix_id("indicator"),
            "pattern":f"[url:value = '{indicator}']"
         },
         "Email Addresses": {
            "type": "indicator",
            "id": self.generate_stix_id("indicator"),
            "pattern":f"[email-message:sender_ref.value = '{indicator}']"
         },
         "MD5 Hashes": {
            "type": "indicator",
            "id": self.generate_stix_id("indicator"),
            "pattern":f"[file:hashes.'MD5' = '{indicator}']"
         },
         "SHA-1 Hashes": {
            "type": "indicator",
            "id": self.generate_stix_id("indicator"),
            "pattern":f"[file:hashes.'SHA-1' = '{indicator}']"
         },
         "SHA256 Hashes": {
            "type": "indicator",
            "id": self.generate_stix_id("indicator"),
            "pattern":f"[file:hashes.'SHA-256' = '{indicator}']"
         },
         "SHA512 Hashes": {
            "type": "indicator",
            "id": self.generate_stix_id("indicator"),
            "pattern":f"[file:hashes.'SHA-512' = '{indicator}']"
         },
         "JARM Hashes": {
            "type": "indicator",
            "id": self.generate_stix_id("indicator"),
            "pattern":f"[jarm-hash:value = '{indicator}']"
         },
         "CVEs": {
            "type":"vulnerability",
            "id": self.generate_stix_id("vulnerability"),
            "name": indicator,
            "external_references": [
               {
                  "source_name": "cve",
                  "external_id": indicator
               }
            ]
         },
         "MITRE ATTACK IDs": {
            "type":"attack-pattern",
            "id": self.generate_stix_id("attack-pattern"),
            "name": f"MITRE ATT&CK Technique: {indicator}",
            "external_references": [
               {
                  "source_name": "mitre-attack",
                  "external_id": indicator,
                  "url": "https://attack.mitre.org/techniques/" + indicator
               }
            ]
         }
      }

      stixx_object = {
      "spec_version": "2.1",
      "pattern_type": "stix",
      "created": self.current_time(),
      "modified": self.current_time(),
      "valid_from": self.current_time(),
      }

      for key, value in STIX_MAPPINGS[indicator_type].items():
         stixx_object[key] = value
      
      return stixx_object
   

   def to_stix(self, group_by_source:bool):
      if group_by_source:
         combined_dict = {}
         for source_name, cur_ioc_dict in self.ioc_dict.items():            
            objects_ar = []
            for key, indicators in cur_ioc_dict.items():
               if indicators:
                  for indicator in indicators:
                     objects_ar.append(self.generate_stix(indicator, key))
            
            if source_name not in cur_ioc_dict:
               combined_dict[f"STIXX Bundle For Source [{source_name}]"] = {
                  "type":"bundle",
                  "id":self.generate_stix_id("bundle")
               }
            combined_dict[f"STIXX Bundle For {source_name}"]["objects"] = objects_ar
            
      else: 
         objects_ar = []
         for source_name, cur_ioc_dict in self.ioc_dict.items():
            for key, indicators in cur_ioc_dict.items():
               if indicators:
                  for indicator in indicators:
                     objects_ar.append(self.generate_stix(indicator, key))
         combined_dict = {
            "type":"bundle",
            "id":self.generate_stix_id("bundle"),
            "objects":objects_ar
         }

      return json.dumps(combined_dict, indent=3)


   def to_json(self, group_by_source:bool):
      combined_dict = {}
      if group_by_source:
         for source_name, cur_ioc_dict in self.ioc_dict.items():
            if source_name not in cur_ioc_dict:
               combined_dict[source_name] = {}
            
            for key, indicators in cur_ioc_dict.items():
               if indicators:
                  if key not in combined_dict[source_name].keys():
                     combined_dict[source_name][key] = []
                  combined_dict[source_name][key] += indicators
      else: 
         for source_name, cur_ioc_dict in self.ioc_dict.items():
            for key, indicators in cur_ioc_dict.items():
               if indicators:
                  if key not in combined_dict.keys():
                     combined_dict[key] = []
                  combined_dict[key] += indicators

      return json.dumps(combined_dict, indent=3)
      

   def export(self, data:str, extract_type:str, file_extension:str):
      timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
      filename = f"{extract_type}[{timestamp}]{file_extension}"
      with open(os.path.join("Extracted",filename),"w") as f:
         f.write(data)
      print("WRITTEN TO FILE!")

      try:
         if self.SETTINGS["Paste-To-Clipboard"]:
            subprocess.run("pbcopy", text=True, input=data)
            print("COPIED TO CLIPBOARD!")
      except:
         pass

      print("\n\n----EXPORTED IOCS----")
      print(data)


   def choose_export_method(self):
      METHODS = {
         "1":[self.just_indicators, "Just-Indicators",".txt"],
         "2":[self.pretty_indicators, "Markdown-Indicators",".md"],
         "3":[self.to_json, "JSON",".json"],
         "4":[self.to_stix, "STIX",".json"],
      }
      
      option = False
      while True:
         print("\n\nChoose a way to export the IOCs: ")
         for key, value in METHODS.items():
            print(f"[{key}]\t{value[1]} -> {value[2]} file & copy 2 clipboard")
         
         option = input("Enter the number of the option you want to choose:\n")
         if option.replace("[","").replace(" ","").replace("]","") in METHODS.keys():
            break
         else:
            print("INVALID CHOICE - please enter the number of the desired option.")

      while True:
         usr_input = input("Group indicators by source name? [y]/[n]\n")
         if usr_input.replace("[","").replace("]","").lower() == "y":
            group_by_source = True
            break
         elif usr_input.replace("[","").replace("]","").lower() == "n":
            group_by_source = False
            break
         else:
            print("INVALID CHOICE")

      data = (METHODS[option][0])(group_by_source)
      self.export(data, METHODS[option][1], METHODS[option][2])



class TextExtractor(HTMLParser):
   def __init__(self):
      super().__init__()
      self.inside_script = False
      self.inside_title = False
      self.title = ""
      self.text = []

   def handle_starttag(self, tag, attrs):
      if tag == 'script':
         self.inside_script = True
      elif tag == 'title':
         self.inside_title = True

   def handle_endtag(self, tag):
      if tag == 'script':
         self.inside_script = False
      elif tag == 'title':
         self.inside_title = False

   def handle_data(self, data):
      if self.inside_title:
         self.title += data.strip()
      elif not self.inside_script:
         self.text.append(data.strip())

   def extract_info_from_website(url):
      try:
         opener = urllib.request.build_opener()
         opener.addheaders = [('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Safari/605.1.1')]
         urllib.request.install_opener(opener)
         # Fetch the HTML content of the webpage
         with urllib.request.urlopen(url) as response:
            html_content = response.read().decode('utf-8')
            
            # Parse the HTML content
            parser = TextExtractor()
            parser.feed(html_content)
            return parser.title, ' '.join(parser.text)
      except Exception as e:
         print("Failed to retrieve the webpage:", e)
         return None, None


if __name__ == "__main__":
   print("Hey, this is a class file!")
   print("Feel free to use this as a package,")
   print("but otherwise please run the [Extractor.py] script to use IOC-Extractor!")
