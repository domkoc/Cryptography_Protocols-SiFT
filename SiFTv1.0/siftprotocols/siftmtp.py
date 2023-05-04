#python3

import socket
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto import Random
from Crypto.PublicKey import RSA


class SiFT_MTP_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg


class SiFT_MTP:
	def __init__(self, peer_socket):
		self.DEBUG = True
		# --------- CONSTANTS ------------
		# self.rcvsqnfile = 'rcvsqn.txt'
		# self.sndsqnfile = 'sndsqn.txt'
		# self.rcvkeyfile = 'rcvkey.txt'
		# self.sndkeyfile = 'sndkey.txt'
		self.rcvsqn = 0
		self.sndsqn = 0
		self.rsaprivfile = 'id_rsa'
		#self.rsapubfile = 'id_rsa.pub'
		self.rsapubfile = 'srvpubkey.txt'
		self.transfer_key = b''
		self.start_sqn = b'\x00\x01'
		self.version_major = 1
		self.version_minor = 0
		self.msg_hdr_ver = b'\x01\x00'
		self.size_msg_hdr = 16
		self.size_msg_hdr_ver = 2
		self.size_msg_hdr_typ = 2
		self.size_msg_hdr_len = 2
		self.size_msg_hdr_sqn = 2
		self.size_msg_hdr_rnd = 6
		self.size_msg_hdr_rsv = 2
		self.size_msg_mac = 12
		self.size_msg_etk = 256
		self.type_login_req =    b'\x00\x00'
		self.type_login_res =    b'\x00\x10'
		self.type_command_req =  b'\x01\x00'
		self.type_command_res =  b'\x01\x10'
		self.type_upload_req_0 = b'\x02\x00'
		self.type_upload_req_1 = b'\x02\x01'
		self.type_upload_res =   b'\x02\x10'
		self.type_dnload_req =   b'\x03\x00'
		self.type_dnload_res_0 = b'\x03\x10'
		self.type_dnload_res_1 = b'\x03\x11'
		self.msg_types = (self.type_login_req, self.type_login_res,
						  self.type_command_req, self.type_command_res,
						  self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
						  self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1)
		# --------- STATE ------------
		self.peer_socket = peer_socket

	# parses a message header and returns a dictionary containing the header fields
	def parse_msg_header(self, msg_hdr):
		parsed_msg_hdr, i = {}, 0
		parsed_msg_hdr['ver'], i = msg_hdr[i:i+self.size_msg_hdr_ver], i+self.size_msg_hdr_ver
		parsed_msg_hdr['typ'], i = msg_hdr[i:i+self.size_msg_hdr_typ], i+self.size_msg_hdr_typ
		parsed_msg_hdr['len'], i = msg_hdr[i:i+self.size_msg_hdr_len], i+self.size_msg_hdr_len
		parsed_msg_hdr['sqn'], i = msg_hdr[i:i+self.size_msg_hdr_sqn], i+self.size_msg_hdr_sqn
		parsed_msg_hdr['rnd'], i = msg_hdr[i:i+self.size_msg_hdr_rnd], i+self.size_msg_hdr_rnd
		parsed_msg_hdr['rsv'], i = msg_hdr[i:i+self.size_msg_hdr_rsv], i+self.size_msg_hdr_rsv
		return parsed_msg_hdr

	def set_transfer_key(self, transfer_key):
		self.transfer_key = transfer_key

	# receives n bytes from the peer socket
	def receive_bytes(self, n):
		bytes_received = b''
		bytes_count = 0
		while bytes_count < n:
			try:
				chunk = self.peer_socket.recv(n-bytes_count)
			except:
				raise SiFT_MTP_Error('Unable to receive via peer socket')
			if not chunk:
				raise SiFT_MTP_Error('Connection with peer is broken')
			bytes_received += chunk
			bytes_count += len(chunk)
		return bytes_received

	# receives and parses message, returns msg_type and msg_payload
	def receive_msg(self):
		try:
			msg_hdr = self.receive_bytes(self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr:
			raise SiFT_MTP_Error('Incomplete message header received')

		parsed_msg_hdr = self.parse_msg_header(msg_hdr)

		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header')

		if parsed_msg_hdr['typ'] not in self.msg_types:
			raise SiFT_MTP_Error('Unknown message type found in message header')

		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')

		# check the sequence number
		if parsed_msg_hdr['typ'] == self.type_login_req:
			if parsed_msg_hdr['sqn'] != self.start_sqn:
				raise SiFT_MTP_Error('Invalid sequence number found in message header')
		else:
			# read the content of the state file
			rcvsqn = self.rcvsqn
			# with open(self.rcvsqnfile, 'rt') as sf:
			# 	rcvsqn = int(sf.readline(), base=10)  # type should be integer
			if int.from_bytes(parsed_msg_hdr['sqn'], byteorder='big') <= rcvsqn:
				raise SiFT_MTP_Error('Invalid sequence number found in message header')

		try:
			msg_body = self.receive_bytes(msg_len - self.size_msg_hdr - self.size_msg_mac)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)

		try:
			msg_mac = self.receive_bytes(self.size_msg_mac)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message mac --> ' + e.err_msg)

		if parsed_msg_hdr['typ'] == self.type_login_req:
			try:
				msg_etk = self.receive_bytes(self.size_msg_etk)
				# load the private key from the private key file and
				# create the RSA cipher object
				keypair = self.load_keypair(self.rsaprivfile)
				rsa_cipher = PKCS1_OAEP.new(keypair)
				key = rsa_cipher.decrypt(msg_etk)
				self.transfer_key = key
				# with open(self.rcvkeyfile, 'w+t') as sf:
				# 	sf.write(key.hex())
			except SiFT_MTP_Error as e:
				raise SiFT_MTP_Error('Unable to receive message etk --> ' + e.err_msg)
		else:
			key = self.transfer_key
			# with open(self.rcvkeyfile, 'rt') as sf:
			# 	key = bytes.fromhex(sf.readline())  # type should be byte string

		if len(msg_body) != msg_len - self.size_msg_hdr - self.size_msg_mac:
			raise SiFT_MTP_Error('Incomplete message body received')

		# verify and decrypt the encrypted payload
		nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd']
		aes = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=self.size_msg_mac)
		aes.update(msg_hdr)
		try:
			decrypted_msg_body = aes.decrypt_and_verify(msg_body, msg_mac)
		except Exception:
			raise SiFT_MTP_Error('Unable to verify mac')

		# update the sequence number
		self.rcvsqn = int.from_bytes(parsed_msg_hdr['sqn'], byteorder='big')
		# with open(self.rcvsqnfile, 'wt') as sf:
		# 	sf.write(str(int.from_bytes(parsed_msg_hdr['sqn'], byteorder='big')))

		# DEBUG
		if self.DEBUG:
			print('MTP message received (' + str(msg_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_body)) + '): ')
			print(msg_body.hex())
			print('------------------------------------------')
		# DEBUG

		return parsed_msg_hdr['typ'], decrypted_msg_body

	# sends all bytes provided via the peer socket
	def send_bytes(self, bytes_to_send):
		try:
			self.peer_socket.sendall(bytes_to_send)
		except:
			raise SiFT_MTP_Error('Unable to send via peer socket')

	# builds and sends message of a given type using the provided payload
	def send_msg(self, msg_type, msg_payload):
		msg_etk = b''
		if msg_type == self.type_login_req:
			msg_hdr_sqn = self.start_sqn
			self.sndsqn = int.from_bytes(msg_hdr_sqn, byteorder='big')
			# with open(self.sndsqnfile, 'w+t') as sf:
			# 	sf.write(str(int.from_bytes(msg_hdr_sqn, byteorder='big')))
			tk = Random.get_random_bytes(32)
			self.transfer_key = tk
			# with open(self.sndkeyfile, 'w+t') as sf:
			# 	sf.write(tk.hex())
			# load the public key from the public key file and
			# create an RSA cipher object
			pubkey = self.load_publickey(self.rsapubfile)
			rsa_cipher = PKCS1_OAEP.new(pubkey)
			# encrypt the AES key with the RSA cipher
			msg_etk = rsa_cipher.encrypt(tk)
		else:
			sndsqn = self.sndsqn
			# with open(self.sndsqnfile, 'rt') as sf:
			# 	sndsqn = int(sf.readline(), base=10)  # type should be integer
			# build message header
			msg_hdr_sqn = (sndsqn + 1).to_bytes(2, byteorder='big')  # next message sequence number (encoded on 4 bytes)

		msg_hdr_rnd = Random.get_random_bytes(6)
		msg_hdr_rsv = b'\x00\x00'
		msg_size = self.size_msg_hdr + len(msg_payload) + self.size_msg_mac + len(msg_etk)
		msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
		msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + msg_hdr_sqn + msg_hdr_rnd + msg_hdr_rsv

		# read the content of the state file
		key = self.transfer_key
		# with open(self.sndkeyfile, 'rt') as sf:
		# 	key = bytes.fromhex(sf.readline())  # type should be byte string

		# encrypt the payload and compute the authentication tag over the header and the payload
		# with AES in GCM mode using nonce = header_sqn + header_rnd
		nonce = msg_hdr_sqn + msg_hdr_rnd
		aes = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=self.size_msg_mac)
		aes.update(msg_hdr)
		encrypted_payload, authtag = aes.encrypt_and_digest(msg_payload)

		# DEBUG
		if self.DEBUG:
			print('MTP message to send (' + str(msg_size) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_payload + authtag + msg_etk)) + '): ')
			print((msg_hdr + encrypted_payload + authtag + msg_etk).hex())
			print('------------------------------------------')
		# DEBUG

		# try to send
		try:
			self.send_bytes(msg_hdr + encrypted_payload + authtag + msg_etk)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)

		# update the sequence number
		self.sndsqn = int.from_bytes(msg_hdr_sqn, byteorder='big')
		# with open(self.sndsqnfile, 'wt') as sf:
		# 	sf.write(str(int.from_bytes(msg_hdr_sqn, byteorder='big')))

	# loads the RSA public key from file
	def load_publickey(self, pubkeyfile):
		with open(pubkeyfile, 'rb') as f:
			pubkeystr = f.read()
		try:
			return RSA.import_key(pubkeystr)
		except ValueError:
			raise SiFT_MTP_Error('Error: Cannot import public key from file ' + pubkeyfile)

	# loads the RSA keypair from file
	def load_keypair(self, privkeyfile):
		with open(privkeyfile, 'rb') as f:
			keypairstr = f.read()
		try:
			return RSA.import_key(keypairstr)
		except ValueError:
			raise SiFT_MTP_Error('Error: Cannot import private key from file ' + privkeyfile)
