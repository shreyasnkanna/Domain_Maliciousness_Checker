import time as t
import requests
import json
import os
import sys
import re
import argparse


def API_Key_Extractor(API_Key):
  
        x = re.search(r"\b[0-9a-f]{64}\b", API_Key)
        if x:
            API_Key =  x.group(0)

            return True
        else:
            return False
            



parser = argparse.ArgumentParser()

parser.add_argument("-iL", "--input_list", help="Enter the Inputs as cmd line arg separated by comma (,) ")



parser.add_argument("-iF", "--input_file", help="Enter the Input File path to read data from. Please Keep the Domain in following syntax : \n\n<Domain>\n\n")


parser.add_argument("-o", "--output_file", help="To run the Master Surface Mapper",required=True)

parser.add_argument("-AK", "--api_key", help="Provide API Key to make API call to VirusTotal",required=True)

#parser.add_argument("-c", "--customer", help="Enter Customer Name or ID", required=True)



args = parser.parse_args()

if(args.input_list is None):
    File_Flag = True
else:
    File_Flag = False
    list_of_input = args.input_list.split(',')





VT_API_Key = args.api_key

API_Key_Validity = API_Key_Extractor(VT_API_Key)
if API_Key_Validity:
    pass
else:
    print("Wrong API key")
    sys.exit()


Output_File = args.output_file

try:
    os.makedirs(os.path.dirname(Output_File))
except:
    pass



while True:
    if os.path.exists(Output_File):
        user_input = input(f"\n\nThe Out path provided already exists. Do you wish overwrite this file.?(Y/N/Q - Quit) : ")
        if(user_input.lower()=='y'):
            break
        elif(user_input.lower()=='n'):
            Output_File = input(f"\n\nPlease provide the New Output Path : ")
        elif(user_input.lower()=='q'):
            print("\n\nQuitting.\n\n")
            sys.exit()
        else:
            pass
    else:
        break



#-------------------------------------reading domains----------------------------------------------

if(File_Flag):
    with open(Input_File_Domain,'r') as g:
            temp=g.read().splitlines()
else:
    temp=list_of_input






#---------------------------------------------------------------------------------------


domain=[]
domains=''
urls=[]

for x in temp:
        x.rstrip()
        if x == '':
                continue
        e=x.split(',')
        e=str(e[0])
        e=e.replace('"','')
        e=e.lower()
        domain+=[e]
        domains+='\n'+str(e)



fault_domains=[]
try:
    with open(Output_File,'w') as f:
        f.write("Blocked_At,Domain,Reason\n")
except:
    print("Failed to write the header!!!")
    Run_Status = False


Count = 0
for i in domain:
        Count += 1
        url='https://www.virustotal.com/api/v3/domains/'+i
        headers={'x-apikey':VT_API_Key}


        print("\n" + str(Count) + ". Searching for " +i+ " domain in VT.")
        try:
                response=requests.get(url,headers=headers)
                f=json.loads(response.content)
        except:
                print("Something wentwrong while making an API call!!!!")

                fault_domains+=[str(i)]
                t.sleep(15)
                continue

        if('error' not in f):
                        print(f)

                        name=f['data']['attributes']['last_analysis_results']

                        for x in name:


                                Reason=str(f['data']['attributes']['last_analysis_results'][str(x)]['category'])
                                if(Reason=='malicious') or (Reason=='suspicious') or (Reason=='phishing') or (Reason=='spam'):
                                        try:

                                            with open(Output_File,'a') as fl:
                                                fl.write(str(x)+","+str(i)+","+Reason + "\n")
                                        except:
                                            print('Failed to write the output')


                                else:
                                        continue


        else:
                fault_domains+=[str(i)]
                print("     --- Something went wrong ")

                message = "'Could not retrieve data from VT Response:"+ str(f['error']['code']) + " for  API key:"+VT_API_Key[0:10]+"'"


        print('Sleeping for 15 seconds...')
        t.sleep(15)


