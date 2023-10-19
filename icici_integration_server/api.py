import rsa
from base64 import b64decode, b64encode
import json
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import requests
from Crypto.Util.Padding import unpad
import frappe,os
aes_key = "1111111111111111"
IV = "8100050000600900".encode("UTF-8")
BLOCK_SIZE = 16

@frappe.whitelist()
def generate_otp(payload):
	data = payload

	def encrypt_key(key):
			site_path  = frappe.utils.get_site_path()
			path = os.path.join(site_path, 'public', "files","icici.pem")
			with open(path, 'rb') as p:
					pk = p.read()
					public_key = rsa.PublicKey.load_pkcs1(pk)
					encrypted_key = rsa.encrypt(key.encode('utf-8'), public_key)
					return b64encode(encrypted_key).decode('utf-8')


	def encrypt_data(data, key):
			# convert to bytes
			padded = pad(IV+data, BLOCK_SIZE)
			# new instance of AES with encoded key
			cipher = AES.new(key.encode("utf-8"), AES.MODE_CBC, IV)
			# now encrypt the padded bytes
			encrypted = cipher.encrypt(padded)
			# base64 encode and convert back to string
			return  b64encode(encrypted).decode('utf-8')
	# data = {
	# 		'CORPID': 'SESPRODUCT',
	# 		'USERID': '389018',
	# 		'AGGRID': 'BULK0040',
	# 		'AGGRNAME': 'GODESI',
	# 		'URN': 'SR238737998',
	# 		'UNIQUEID': '434411211602',
	# 		'AMOUNT': '5.0'
	# }
	encrypted_key = encrypt_key(aes_key)
	encrypted_data = encrypt_data(json.dumps(data).encode("UTF-8"), aes_key)

	headers = {
				"accept": "application/json",
				"content-type": "application/json",
				"apikey": "EA8zlrPPniGBmUDdT2FcCP7nUPKQ1ner"
			}

	url = "https://apibankingonesandbox.icicibank.com/api/Corporate/CIB/v1/Create"
	#encrypted_data = "EN/BtfZs/WodxG1mkHvusX0WLDri1dWv6sILK5Lu1U8aT5aGmlE2h+Q3dL/5KG1oioOa1DrxFS3lrw67X0XnExGbhkQJWlX/qH6pICz8xa4fes3xs1OpUp0+vINQjXjyE6QOuI+kYwxcXdgYFxBTWLkRSqxcI+Z63DIVPmEbPmcnNJdihCb9Wj4egDKJwvgsNNYM6lAwsc+XP0NS1+YlpQHUTfgjGwCCBgRuCn1SzQM="
	request_payload = {
			"requestId": "1234567",
			"service": "",
			"oaepHashingAlgorithm": "NONE",
			"encryptedKey": encrypted_key,
			"encryptedData": encrypted_data,
			"clientInfo": "",
			"optionalParam": "",
			"iv": ""
			}

	response = requests.post(url, headers=headers, data=json.dumps(request_payload))

	def get_decrypted_response(response=None):
			if response:
					response=json.loads(response.text)
					decrypted_key=decrypt_key(response.get("encryptedKey"))
					return decrypt_data(response.get('encryptedData'), decrypted_key.encode("utf-8"))
	def decrypt_key(key):
			site_path  = frappe.utils.get_site_path()
			path = os.path.join(site_path, 'public', "files","godesi_private_key_rsa.pem")
			with open(path, 'rb') as p:
					pk = p.read()
					#pk = pk.replace('\\n', '\n').decode('ascii')
					private_key = rsa.PrivateKey.load_pkcs1(pk)
					decrypted_key = rsa.decrypt(b64decode(key), private_key).decode('utf-8')
					return decrypted_key
	unpad_pkcs5 = lambda s: s[:-ord(s[len(s) - 1:])]
	def decrypt_data(data, key):
			message = b64decode(data)
			cipher= AES.new(key, AES.MODE_CBC, data[0:16].encode("UTF-8"))
			decrypted = unpad_pkcs5(cipher.decrypt(message)[16:])
			decrypted = decrypted.decode("UTF-8")
			decrypted = json.loads(json.dumps(decrypted))
			print("Decrypted : ",decrypted )
			return decrypted

	if response.ok:
		decrypted_response = get_decrypted_response(response)
		return decrypted_response

@frappe.whitelist(allow_guest = True)
def make_payment(payload):
	content = ""
	data = payload
	# data = {
	# 		"FILE_DESCRIPTION":"TESTDECRIPT011",
	# 		"CORP_ID": "SESPRODUCT",
	# 		"USER_ID": "389018",
	# 		"AGGR_ID": "BULK0040",
	# 		"AGGR_NAME": "GODESI",
	# 		"URN": "SR238737998",
	# 		"UNIQUE_ID": "434411211603",
	# 		"AGOTP":"852472",
	# 		"FILE_NAME":"TESTDES011.txt",
	# 		"FILE_CONTENT":content
	# }
	#print(data)
	
	def encrypt_key(key):
			site_path  = frappe.utils.get_site_path()
			path = os.path.join(site_path, 'public', "files","icici.pem")
			with open(path, 'rb') as p:
					public_key = rsa.PublicKey.load_pkcs1(p.read())
					encrypted_key = rsa.encrypt(key.encode('utf-8'), public_key)
					return b64encode(encrypted_key).decode('utf-8')

	def encrypt_data(data, key):
			# convert to bytes
			padded = pad(IV + data, BLOCK_SIZE)
			# new instance of AES with encoded key
			cipher = AES.new(key.encode("utf-8"), AES.MODE_CBC, IV)
			# now encrypt the padded bytes
			encrypted = cipher.encrypt(padded)
			# base64 encode and convert back to string
			return  b64encode(encrypted).decode('utf-8')

	encrypted_key = encrypt_key(aes_key)
	print(encrypted_key)
	encrypted_data = encrypt_data(json.dumps(data).encode("UTF-8"), aes_key)
	print(encrypted_data)
	headers = {
				"accept": "application/json",
				"content-type": "application/json",
				"apikey": "EA8zlrPPniGBmUDdT2FcCP7nUPKQ1ner"
			}

	url =  "https://apibankingonesandbox.icicibank.com/api/v1/cibbulkpayment/bulkPayment"

	request_payload = {
			"requestId": "1234568",
			"service": "",
			"oaepHashingAlgorithm": "NONE",
			"encryptedKey": encrypted_key,
			"encryptedData": encrypted_data,
			"clientInfo": "",
			"optionalParam": "",
			"iv": ""
			}

	response = requests.post(url, headers=headers, data=json.dumps(request_payload))

	print("Response:", response.text)

	def get_decrypted_response(response=None):
			if response:
					response=json.loads(response.text)
					decrypted_key=decrypt_key(response.get("encryptedKey"))
					return decrypt_data(response.get('encryptedData'), decrypted_key.encode("utf-8"))
			# else:
			#         response={"requestId":"1234567","encryptedKey":"Gl0ehvfwRzZNmglx5JXw+v25qjLf+2cfz08GRRx6zAAeGG1iX0IxJXL/1zgdyr/R2ho9VCHYZyB8MHrUiJEYMVrtxlmSWVxC+tEVGfIn2PHbNPJtynKCKA4HtEt7+1utHbDgAX0+405GUnqX3D>
			#         decrypted_key=decrypt_key(response.get("encryptedKey"))
			#         decrypt_data(response.get('encryptedData'), decrypted_key.encode("utf-8"))
	def decrypt_key(key):
			site_path  = frappe.utils.get_site_path()
			path = os.path.join(site_path, 'public', "files","godesi_private_key_rsa.pem")
			with open(path, 'rb') as p:
					private_key = rsa.PrivateKey.load_pkcs1(p.read())
					decrypted_key = rsa.decrypt(b64decode(key), private_key).decode('utf-8')
					return decrypted_key

	unpad_pkcs5 = lambda s: s[:-ord(s[len(s) - 1:])]

	def decrypt_data(data, key):
			message = b64decode(data)
			cipher= AES.new(key, AES.MODE_CBC, data[0:16].encode("UTF-8"))
			decrypted = unpad_pkcs5(cipher.decrypt(message)[16:])
			decrypted = decrypted.decode("UTF-8")
			decrypted = json.loads(json.dumps(decrypted))
			print("Decrypted : ",decrypted )
			return decrypted

	if response.ok:
			decrypted_response=get_decrypted_response(response)
			return str(decrypted_response)

@frappe.whitelist(allow_guest = True)
def get_status(payload):
	data = payload
	# data = {
	# 		"CORPID":"SESPRODUCT",
	# 		"USERID":"SESPRODUCT.389018",
	# 		"AGGRID":"BULK0040",
	# 		"URN":"SR238737998",
	# 		"FILESEQNUM":"68196",
	# 		"ISENCRYPTED":"N"
	# }

	def encrypt_key(key):
			site_path  = frappe.utils.get_site_path()
			path = os.path.join(site_path, 'public', "files","icici.pem")
			with open(path, 'rb') as p:
					public_key = rsa.PublicKey.load_pkcs1(p.read())
					encrypted_key = rsa.encrypt(key.encode('utf-8'), public_key)
					return b64encode(encrypted_key).decode('utf-8')

	def encrypt_data(data, key):
			# convert to bytes
			padded = pad(IV + data, BLOCK_SIZE)
			# new instance of AES with encoded key
			cipher = AES.new(key.encode("utf-8"), AES.MODE_CBC, IV)
			# now encrypt the padded bytes
			encrypted = cipher.encrypt(padded)
			# base64 encode and convert back to string
			return  b64encode(encrypted).decode('utf-8')

	encrypted_key = encrypt_key(aes_key)
	encrypted_data = encrypt_data(json.dumps(data).encode("UTF-8"), aes_key)

	headers = {
				"accept": "application/json",
				"content-type": "application/json",
				"apikey": "EA8zlrPPniGBmUDdT2FcCP7nUPKQ1ner"
	}

	url =  "https://apibankingonesandbox.icicibank.com/api/v1/ReverseMis"
	request_payload = {
			"requestId": "1234567",
			"service": "",
			"oaepHashingAlgorithm": "NONE",
			"encryptedKey": encrypted_key,
			"encryptedData": encrypted_data,
			"clientInfo": "",
			"optionalParam": "",
			"iv": ""
			}

	response = requests.post(url, headers=headers, data=json.dumps(request_payload))

	print("Response:", response.text)
	def get_decrypted_response(response=None):
			if response:
					response=json.loads(response.text)
					decrypted_key=decrypt_key(response.get("encryptedKey"))
					return decrypt_data(response.get('encryptedData'), decrypted_key.encode("utf-8"))
			#else:
			#       response={"requestId":"1234567","encryptedKey":"YybKyVbjQBK3ItF5Ne9K2NASptz917V5X2OZ7DJHRxOapuGDT7h4UzHuyTHoZvSocWYZUvqgYPoyyDoPNktivi68cOhnSLwof13JWQwN3VTuXhrZ2mB8zN0nIBwbJfyk2WwB5xiHIg4KV2/LSQ>
			#       print(response.get("encryptedKey"))
			#       decrypted_key=decrypt_key(response.get("encryptedKey"))
			#       decrypt_data(response.get('encryptedData'), decrypted_key.encode("utf-8"))
	def decrypt_key(key):
			site_path  = frappe.utils.get_site_path()
			path = os.path.join(site_path, 'public', "files","godesi_private_key_rsa.pem")
			with open(path, 'rb') as p:
					private_key = rsa.PrivateKey.load_pkcs1(p.read())
					decrypted_key = rsa.decrypt(b64decode(key), private_key).decode('utf-8')
					return decrypted_key
	unpad_pkcs5 = lambda s: s[:-ord(s[len(s) - 1:])]
	def decrypt_data(data, key):
			message = b64decode(data)
			cipher= AES.new(key, AES.MODE_CBC, data[0:16].encode("UTF-8"))
			decrypted = unpad_pkcs5(cipher.decrypt(message)[16:])
			decrypted = decrypted.decode("UTF-8")
			decrypted = json.loads(json.dumps(decrypted))
			print("Decrypted : ",decrypted )
			return decrypted

	if response.ok:
			decrypted_response=get_decrypted_response(response)
			return decrypted_response

	#else:
	#       decrypted_response=get_decrypted_response()

