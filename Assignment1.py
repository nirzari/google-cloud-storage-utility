#NAME: NIRZARI IYER
#Assignment-1
#ID NUMBER: 1001117633
#BATCH TIME- 6:00 to 8:00 p.m.
#import statements.
import argparse
import httplib2
import os
import sys
import json
import time
import datetime
import io
import hashlib
import sys
#Google apliclient (Google App Engine specific) libraries.
from apiclient import discovery
from oauth2client import file
from oauth2client import client
from oauth2client import tools
from apiclient.http import MediaIoBaseDownload
#pycrypto libraries.
from Crypto import Random
from Crypto.Cipher import AES

# Encryption using AES

#Initial password to create a key
def getpass():
    password = raw_input("Enter Password:")
    key = hashlib.sha256(password).digest()
    return key

#this implementation of AES works on blocks of "text", put "0"s at the end if too small.
def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

#Function to encrypt the message
def encrypt(message, key, key_size=256):
    message = pad(message)
    #iv is the initialization vector
    iv = Random.new().read(AES.block_size)
    #Entire message is encrypted
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

#Function to decrypt the message
def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")

#Function to encrypt a given file
def encrypt_file(file_name, key):
    #Open file to read content in the file, encrypt the file data.
    f = open (file_name,'rb')
    filecontent = f.read()
    message = str(filecontent)
    emessage = encrypt(message, key, key_size=256)
    f.close()
    #create a new file and then write the encrypted data to it, return the encrypted file name.
    efile = open (file_name, 'wb')
    efile.write(emessage)
    return efile.name    
    
#Function to decrypt a given file.
def decrypt_file(file_name, key):
    #open file read the data of the file, decrypt the file data.
    f = open (file_name,'w')
    filecontent = f.read()
    ciphertext = str(filecontent)
    dmessage = decrypt(ciphertext, key)
    f.close()  
    #create a new file and then write the decrypted data to the file.
    dfile = open ('dfile','w')
    dfile.write(dmessage)
    dfile.close()
    return dfile.name
    
_BUCKET_NAME = 'nizi1' #name of my google bucket.
_API_VERSION = 'v1'

# Parser for command-line arguments.
parser = argparse.ArgumentParser(
    description=__doc__,
    formatter_class=argparse.RawDescriptionHelpFormatter,
    parents=[tools.argparser])


# client_secret.json is the JSON file that contains the client ID and Secret.
CLIENT_SECRETS = os.path.join(os.path.dirname(__file__), 'client_secret.json')

# Set up a Flow object to be used for authentication.
# Add one or more of the following scopes. 
# These scopes are used to restrict the user to only specified permissions (in this case only to devstorage) 
FLOW = client.flow_from_clientsecrets(CLIENT_SECRETS,
  scope=[
      'https://www.googleapis.com/auth/devstorage.full_control',
      'https://www.googleapis.com/auth/devstorage.read_only',
      'https://www.googleapis.com/auth/devstorage.read_write',
    ],
    message=tools.message_if_missing(CLIENT_SECRETS))

#Downloads the specified object from the given bucket and deletes it from the bucket.
def get(service):
    #User can be prompted to input file name(using raw_input) that needs to be be downloaded,
    file_name = raw_input("Enter file name to be downloaded:")
    key = getpass()
    try:
        # Get Metadata
        req = service.objects().get(
        	bucket=_BUCKET_NAME,
        	object=file_name,
        	fields='bucket,name,metadata(my-key)',    
        
                )                   
	resp = req.execute()
	print json.dumps(resp, indent=2)

# Get Payload Data
	req = service.objects().get_media(
        	bucket=_BUCKET_NAME	,
        	object=file_name,
		)    
# The BytesIO object may be replaced with any io.Base instance.
	fh = io.BytesIO()
	downloader = MediaIoBaseDownload(fh, req, chunksize=1024*1024) #show progress at download
	done = False
	while not done:
	    status, done = downloader.next_chunk()
	    if status:
	        print 'Download %d%%.' % int(status.progress() * 100)
	    print 'Download Complete!'
	dec = decrypt(fh.getvalue(),key)
#decodefile = '/home/nirzari/Desktop/Project1/' + file_name
	with open(file_name, 'wb') as fo:
             fo.write(dec)
    	print json.dumps(resp, indent=2)

    except Exception as e:
        print ("File not found")
    except client.AccessTokenRefreshError:
        print ("Error in the credentials")
   
#Puts a object into file after encryption and deletes the object from the local PC.
def put(service):
    file_name = raw_input("Enter file name to be uploaded:")
    key = getpass()
    try:
        file_name = encrypt_file(file_name, key)
    	req = service.objects().insert(
    	bucket=_BUCKET_NAME,
    	name=file_name,
    	media_body=file_name)
    	resp = req.execute()
    	print json.dumps(resp, indent=2)
    	os.remove(file_name)
    
    except Exception as e:
        print ("File not found")    
    except client.AccessTokenRefreshError:
    	print ("Error in the credentials")
    

#Lists all the objects from the given bucket name
def listobj(service):
    '''List all the objects that are present inside the bucket. '''
    try:
    	fields_to_return = 'nextPageToken,items(bucket,name,metadata(my-key))'
    	req = service.objects().list(
        bucket=_BUCKET_NAME,
        fields=fields_to_return,    # optional
        maxResults=42)              # optional

# If you have too many items to list in one request, list_next() will
# automatically handle paging with the pageToken.
    	while req is not None:
    		resp = req.execute()
                for object in resp["items"]:
    		    print object["name"]
      		req = service.objects().list_next(req, resp)

    except Exception as e:
        print ("No files found")
    except client.AccessTokenRefreshError:
    	print ("Error in the credentials")
    

#This deletes the object from the bucket
def deleteobj(service):
    '''Prompt the user to enter the name of the object to be deleted from your bucket.Pass the object name to the delete() method to remove the object from your bucket'''
    file_name = raw_input("Enter the filename to be deleted:")
    try: 
        service.objects().delete(
        bucket=_BUCKET_NAME,
        object=file_name).execute()
        os.remove(file_name)

    except Exception as e:
        print ("File not found")
    except client.AccessTokenRefreshError:
        print ("Error in the credentials")
	
def main(argv):
  # Parse the command-line flags.
  flags = parser.parse_args(argv[1:])

  #sample.dat file stores the short lived access tokens, which your application requests user data, attaching the access token to the request.
  #so that user need not validate through the browser everytime. This is optional. If the credentials don't exist 
  #or are invalid run through the native client flow. The Storage object will ensure that if successful the good
  # credentials will get written back to the file (sample.dat in this case). 
  storage = file.Storage('sample.dat')
  credentials = storage.get()
  if credentials is None or credentials.invalid:
    credentials = tools.run_flow(FLOW, storage, flags)

  # Create an httplib2.Http object to handle our HTTP requests and authorize it
  # with our good Credentials.
  http = httplib2.Http()
  http = credentials.authorize(http)

  # Construct the service object for the interacting with the Cloud Storage API.
  service = discovery.build('storage', _API_VERSION, http=http)

  #Store the option and name of the function as the key value pair in the dictionary.
  condition = True
  while condition: 
    options = {1: put, 2: get, 3: listobj, 4: deleteobj, 5: exit}
    print "Menu \n 1: Put \n 2: get \n 3: listobj \n 4: deleteobj \n 5: exit"
    option = raw_input("Enter your input choice:")
    if option == "5":
        sys.exit(0)
    elif option == "1" or option == "2" or option == "3" or option == "4":
        #for example if user gives the option 1, then it executes the below line as put(service) which calls the put function defined above.
        options[int(option)](service)
    else:
        print "Enter Valid choice"

if __name__ == '__main__':
  main(sys.argv)
# [END all]

#References:
#https://cloud.google.com/storage/docs/json_api/v1/objects/insert

