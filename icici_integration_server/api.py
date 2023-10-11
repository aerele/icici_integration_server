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
	return [response,"\n\nResponse:",response.text]
	def get_decrypted_response(response=None):
			if response:
					return response
					response=json.loads(response.text)
					decrypted_key=decrypt_key(response.get("encryptedKey"))
					return decrypt_data(response.get('encryptedData'), decrypted_key.encode("utf-8"))
			# else:
			# 		pass
					# response={"requestId":"1234567","service":"CIB","oaepHashingAlgorithm":"NONE","encryptedKey":"ShN5izfihKxeQTqap91IQ3QIaKoaH3ls/mbKaVgvaiaJFID4l6KTz9FBGSqU3f4LuitC8sqolkq5rInwM/FqA28wJEipqYYz2C8o>
					# print(response.get("encryptedKey"))
					# decrypted_key=decrypt_key(response.get("encryptedKey"))
					# decrypt_data(response.get('encryptedData'), decrypted_key.encode("utf-8"))
	def decrypt_key(key):
			site_path  = frappe.utils.get_site_path()
			path = os.path.join(site_path, 'public', "files","godesi_private_key_rsa.pem")
			with open(path, 'rb') as p:
					pk = p.read()
					#pk = pk.replace('\\n', '\n').decode('ascii')
					private_key = rsa.PrivateKey.load_pkcs1(pk)
					frappe.log_error("key - {0}".format(key))
					decrypted_key = rsa.decrypt(b64decode(key), private_key).decode('utf-8')
					return decrypted_key

	def decrypt_data(data, key):
			message = b64decode(data)
			cipher= AES.new(key, AES.MODE_CBC, IV)
			decrypted = cipher.decrypt(message)
			return decrypted
			#decoded_payload = decrypted.decode('ISO-8859-1')
			#print(decoded_payload)
	#       print(unpad(decrypted, BLOCK_SIZE).decode("utf-8"))
	if response.ok:
		decrypted_response = get_decrypted_response(response)
		return decrypted_response
	#else:
	#       decrypted_response=get_decrypted_response()






