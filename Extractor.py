from extractor_class import IOC_GROUP, TextExtractor

if __name__ == "__main__":   
   my_group = IOC_GROUP()
   print("<-----IOC-Extractor (c)2024----->")

   while True:
      user_input = input("\nEnter source(s) to load. Separate each source with a new line. Enter a blank line to stop entering. \nAcceptable sources:\n- filename of plain text file inside Sources folder\n- full path of a plain text file\n- url\n")
      if user_input.replace(" ","") == "":
         break
      else:
         source_name = input("Enter a name for this source:\n")
         my_group.load_source(user_input,source_name)

   
   my_group.extract_iocs()
   my_group.choose_export_method()
   