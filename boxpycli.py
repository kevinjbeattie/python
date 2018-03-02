# -*- coding: utf-8 -*-
''' Box Python CLI Tool
	 Author: Kevin Beattie
	   Date: 03/01/2018
Description: An python CLI utility to read and report on files and folders in Box. Requires an account on Box.com using OAuth2 with JWT. See doc links below for more info.
  Doc Links: 1) Box API Reference - https://docs.box.com/reference
  			 2) Box Developer Docs - https://developer.box.com/docs/configuring-box-platform
 Once You've Created an App on Box at https://app.box.com/developers/console/ you will need to setup an RSA Key. 
 A JSON file will be downloaded which contains the approporate information. This JSON file should be in the same directory as this program.

'''    
import time, json, requests, jwt, uuid, datetime, os, sys, getopt, argparse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from validate_email import validate_email
from bcolors import *

with open('secrets.json') as secrets_file:
	try:
		data = json.load(secrets_file)
		client_id = data['boxAppSettings']['clientID']
		client_secret = data['boxAppSettings']['clientSecret']
		private_key = data['boxAppSettings']['appAuth']['privateKey']
		private_key = str(private_key)
		key_password = str(data['boxAppSettings']['appAuth']['passphrase'])
	except:
		bcolors.color('FAIL',"Error: Unable to read secrets file or file is malformed.")

# Variables
api_url = "https://api.box.com/oauth2/token"
usr_url = "https://api.box.com/2.0/users/"
group_url = "https://api.box.com/2.0/groups"
folder_url = "https://api.box.com/2.0/folders/"
file_url = "https://api.box.com/2.0/files/"
aud = "https://api.box.com/oauth2/token"
iat = int(time.time())
iat_time = datetime.datetime.fromtimestamp(iat).strftime('%c')
exp = iat + 60
exp_time = datetime.datetime.fromtimestamp(exp).strftime('%c')
jti = (uuid.uuid4()).hex # Generates a random hex for the jti
key = load_pem_private_key(private_key, key_password, default_backend())
tenant_enterprise_id = "41769067" # Go to https://app.box.com/master/settings to get the correct ID
box_sub_type = "enterprise"
enterprise_assertion = jwt.encode({"iss": client_id,"sub": tenant_enterprise_id,"box_sub_type": box_sub_type, "aud": api_url,"jti": jti,"exp": exp,}, key, algorithm='RS256', headers={"alg": "RS256","typ": "JWT"})
auth_data = [
  ('grant_type', 'urn:ietf:params:oauth:grant-type:jwt-bearer'),
  ('client_id', client_id),
  ('client_secret', client_secret),
  ('assertion', enterprise_assertion),
]

### ==== BEGIN DEFINITIONS ===
def usage():
	print '''\nBox Python CLI Tool v0.0.0.1
Authored by Kevin Beattie
Requires Python 2.7.6 (minimum)

Usage: boxpycli.py [OPTIONS]

Examples:
  -h 	Display this help file
  -u USER, --user USER  Generate a report on a user
  -d, --debug 	Generate extra data for debugging purposes
	'''

# Get an access token
def authorize(data):
	if (debug):
		bcolors.color('WARNING',"(DEBUG) Running Function: authorize ")
		bcolors.color('HEADER',"Data Received: " + str(data))
	r = requests.post(api_url, data=data)
	try:
		load = r.json()
		if 'access_token' in load:
			load.has_key('access_token')
			token = load['access_token']
			if (debug):
				bcolors.color('HEADER',"(DEBUG) JSON Data Returned from API: " + str(r.json()) + "\n Access Token: " + str(token))
			return token
		else:
			bcolors.color('FAIL',"ERROR: " + load['error_description'])
			sys.exit(1)
	except ValueError, e:
		return False

# Format errors to stdout
def is_error(err):
	bcolors.color('FAIL',"ERROR: " + str(err))
	usage()
	sys.exit(2)

# Validate an email address conforms to a specific domain (useful for enterprise accounts)
def is_valid_email(input_string):
	result = validate_email(input_string)
	if "gmail.com" not in input_string:
		msg_str = "Email address \'" + str(input_string) + "\' does not belong to Domain.com"
		bcolors.color('FAIL',"ERROR: " + str(msg_str))
		usage()
		return False
	else:
		if (result):
			return True
		else:
			msg_str = "Malformed email address \'" + str(input_string) + "\'"
			bcolors.color('FAIL',"ERROR: " + str(msg_str))
			usage()
			return False

# Get info on a user (requires a token)
def do_user_lookup(user):
	auth_token = authorize(auth_data)
	user_id = get_user_id(auth_token,user)
	user_token = get_user_token(user_id)
	if user_token:
		msg_str = "Acquired access token for \'" + str(user) + "\' : " + str(user_token)
		bcolors.color('OKGREEN',"SUCCESS: " + str(msg_str))
		return user_token
	else:
		msg_str = "Unable to acquire token for \'" + str(user) + "\'"
		bcolors.color('FAIL',"ERROR: " + str(msg_str))
		sys.exit(1)

# Get the ID for a user by email address
def get_user_id(access_token, user_email):
	if (debug):
		bcolors.color('WARNING',"(DEBUG) Running Function: get_user_id ")
		bcolors.color('HEADER',"Data Received: \n access_token: " + str(access_token) + "\n user_email: " + str(user_email))
	user_email = user_email.replace('@', '%40')
	api_url = usr_url + "?filter_term="+ str(user_email) + "&fields=id"
	token = "Bearer " + str(access_token)
	headers = {
	    'Authorization': token,
	}
	r = requests.get(api_url, headers=headers)
	try:
		load = r.json()
		if load.has_key('entries'):
			sub_values = load['entries']
			for value in sub_values:
				if 'id' in value:
					return value['id']
				else:
					bcolors.color('FAIL',"Failed to find \'id\' value in the data: " + str(sub_values))
		if (debug):		
			bcolors.color('HEADER',"API URL: " + str(api_url) + "\nAPI Response:" + str(r) + " JSON Data Received: " + str(load) + " User ID: " + str(user_id))
	except ValueError, e:
		return False

# Get a token for a user (requires the ID for the user)
def get_user_token(user_id):
	box_sub_type = "user"
	tenant_enterprise_id = user_id
	jti = (uuid.uuid4()).hex
	enterprise_assertion = jwt.encode({"iss": client_id,"sub": tenant_enterprise_id,"box_sub_type": box_sub_type, "aud": api_url,"jti": jti,"exp": exp,}, key, algorithm='RS256', headers={"alg": "RS256","typ": "JWT"})
	data = [
	  ('grant_type', 'urn:ietf:params:oauth:grant-type:jwt-bearer'),
	  ('client_id', client_id),
	  ('client_secret', client_secret),
	  ('assertion', enterprise_assertion),
	]	
	if (debug):
		bcolors.color('WARNING',"(DEBUG) Running Function: get_user_token ")
		bcolors.color('HEADER',"Data Received: \n user_id: " + str(user_id) + "\nBox Sub Type: " + str(box_sub_type))
		bcolors.color('HEADER',"Box App User: " + str(tenant_enterprise_id) + "\nEnterprise Assertion: " + str(enterprise_assertion))
	try:
		token = authorize(data)
		if(token):
			return token
		else:
			bcolors.color('FAIL',"ERROR: Failed to get a token for the requested user.")
			sys.exit(1)
	except ValueError, e:
		return False

### ==== BEGIN MAIN ===
def main(argv):
	try:
		global debug
		debug = False # Debugging disabled by default, use flag --debug to turn on debugging
		parser = argparse.ArgumentParser(description="Box Python CLI Tool v0.0.0.1, Authored by Kevin Beattie <kevinjbeattie@gmail.com>, Requires (Min.) Python 2.7.6")
		parser.add_argument("-u", "--user", action="store", dest="user", type=str, help="Generate a report on a user")
		parser.add_argument("-d", "--debug", action="store_true", help="Runs tests and displays useful debugging information")
		args = parser.parse_args()
		if args.debug:
			debug = True  # Enable debugging
			bcolors.color('OKGREEN',"Debugging: On")
			### Print JWT Debug Info if Debugging is Enabled
			heading = """####################################################################'
"Application Client ID (issuer): """ + str(client_id) + """
"JWT Audience: """ + str(api_url) + """
"JWT Issued at Time (UNIX Epoch): """ + str(iat) + """
"JWT Issued at Time: """ + str(iat_time) + """
"Expiry Time for JWT (UNIX Epoch): """ + str(exp) + """
"Expiry Time for JWT: """ + str(exp_time) + """
"jti unique identifier: """ + str(jti) + """
'#####################################################################"""
			bcolors.color('BOLD',str(heading))
		elif args.user:
			user_email = is_valid_email(args.user)
			if (user_email):
				do_user_lookup(args.user)
		else:
			usage()
	except getopt.GetoptError as err:
		is_error(err)
		sys.exit(2)

if __name__ == '__main__':
	args = sys.argv[1:]
	if args:
		main(args)
	else:
		usage()
	bcolors.color('OKGREEN',"End of Program")