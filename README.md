# Domain_Maliciousness_Checker
### Author : Shreyas.N

This tool will check whether the provided domain is marked malicious or not. 
This tool accepts single/list of domains as  command line argument or pass list of domain through input file.

#### Python Requirements:
* argparse
* requests

#### Additional Requirements:
* Virus Total API key

#### Options Available:
```
usage: Domain_Rep_Check.py [-h] [-iL INPUT_LIST] [-iF INPUT_FILE] -o OUTPUT_FILE -AK API_KEY

optional arguments:
  -h, --help            show this help message and exit
  -iL INPUT_LIST, --input_list INPUT_LIST
                        Enter the Inputs as cmd line arg separated by comma (,)
  -iF INPUT_FILE, --input_file INPUT_FILE
                        Enter the Input File path to read data from. Please Keep the Domain in following syntax : <Domain>
  -o OUTPUT_FILE, --output_file OUTPUT_FILE
                        To run the Master Surface Mapper
  -AK API_KEY, --api_key API_KEY
                        Provide API Key to make API call to VirusTotal
```

#### Tool Usage:
To pass single/list of domains as argument:

``` $ python3 Domain_Rep_Check.py -iL <domain1>,<domain2> -o <Output File Path> -AK <VirusTotal API Key>```

To pass list of domains inside the file:

``` $ python3 Domain_Rep_Check.py -iF <Input File Path> -o <Output File Path> -AK <VirusTotal API Key>```

