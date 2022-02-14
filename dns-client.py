"""
DNS Client

A simple DNS Client similar to nslookup
It would handle all records
1. Check if Interactive or non-interactive mode
2. Provide maximum possible functions in interactive mode
	-Get the hostname from user
	-Report if any syntax error
	-Check query type
	-Generate a DNS-Query out of this hostname
	-Send the query to DNS-Server
	-Analyse the response
	-Present the response appropriately to the user
"""

import binascii
import socket
import sys
import ipaddress

server = '127.0.0.1'												#Default
port = 12000
query = '0001'
dnsserver = ''
timeout = 10														#Setting the timeout
rec = '1'

def send_udp_message(message, address, port, timeout):
	clientsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	clientsocket.settimeout(timeout)
	try:
		clientsocket.sendto(binascii.unhexlify(message), (address, port))			#sending it in binary format
		clientsocket.sendto(str(timeout).encode(), (address, port))
		data, _ = clientsocket.recvfrom(4096)
	except socket.timeout:
		return None
	finally:
		clientsocket.close()
	return binascii.hexlify(data).decode("utf-8")

def error_condition(errorcode):
	if errorcode == 0:
		error = "NOERROR"	#DNS Query completed successfully
	elif errorcode == 1:
		error = "FORMERR"	#DNS Query Format Error
	elif errorcode == 2:
		error = "SERVFAIL"	#Server failed to complete the DNS request
	elif errorcode == 3:
		error = "NXDOMAIN"	#Domain name does not exist.
	elif errorcode == 4:
		error = "NOTIMP"	#Function not implemented
	elif errorcode == 5:
		error = "REFUSED"	#The server refused to answer for the query
	return error


def find_ip(url, server, port, timeout, query):
	QID = '1010101111001101'
	QQR = '0'
	QOpcode = '0000'
	QAA = '0'
	QTC = '0'
	QRD = rec
	QRA = '0'
	QZ = '000'
	QRcode = '0000'
	QQdcount = '0000000000000001'
	QAncount = '0000000000000000'
	QNscount = '0000000000000000'
	QArcount = '0000000000000000'

	query1_binary = QID + QQR + QOpcode + QAA + QTC + QRD + QRA + QZ + QRcode + QQdcount + QAncount + QNscount + QArcount	#concatinating and creating query header
	query1_hex = hex(int(query1_binary, 2)).lstrip("0x").rstrip("L")

	# lstrip helps remove "0x" from the left
    # rstrip helps remove "L" from the right,
    # L represents a long number
	
	QQname = ''
	words = url.split(".")									#splitting the url and adding length in each field
	for word in words:
		he = hex(len(word)).lstrip("0x").rstrip("L")
		if len(he) == 1:
			he = '0' + he
		QQname = QQname + he
		for letter in word:
			QQname = QQname + hex(ord(letter)).lstrip("0x").rstrip("L")
	QQname = QQname + '00'
	QQclass_hex = '0001'
	
	QQtype_hex = query

	if (QQtype_hex == '001c' or QQtype_hex == '0001')	and atype == 0:	#for type aaaa
		query2_hex = QQname + '001c' + QQclass_hex
		message = query1_hex + query2_hex
		response = send_udp_message(message, server, port, timeout)
		if response == None:
			return None, None, None, None
		
		Rcode = int(response[7])
		error = error_condition(Rcode)
		res_binary = ''
		for letter in response:
			l = str(bin(int(letter, 16))).lstrip('0b').zfill(4)
			res_binary = res_binary + l
		RAA = res_binary[21]
		if QQtype_hex == '001c':
			IP_list = []
			canonical_list = []
		res = response
		RRR = res[-56:]
		res = res[0:len(res)-56]
		while RRR[4:8] == '001c':
			IPv6_unform = RRR[-32:]
			n = 0
			IPv6_form = ''
			for i in range(0,8):
				part = IPv6_unform[n:n+4].lstrip('0')
				if part == '':
					part = '0'
				IPv6_form = IPv6_form + part + ":"
				n += 4
			IPv6_form = IPv6_form[0:len(IPv6_form)-1]
			IPv6 = IPv6_form.replace(":0:0:0:0:0:0:","::")	
			IPv6 = IPv6.replace(":0:0:0:0:0:","::")
			IPv6 = IPv6.replace(":0:0:0:0:","::")
			IPv6 = IPv6.replace(":0:0:0:","::")
			IPv6 = IPv6.replace(":0:0:","::")
			
			name_ptr = int(RRR[2:4], 16) * 2
			cn = response[name_ptr:]
			name = ''
			if canonical_list != []:
				while cn:
					s = int(cn[0:2],16)
					s_end = 2*s + 2
					name = name + bytes.fromhex(cn[2:s_end]).decode('utf-8')
					cn = cn[s_end:]
					name = name + '.'
					if cn[0:2] == 'c0':
						ptr = int(cn[2:4],16)
						cn = message[ptr*2:(len(message)-10)]
						while cn:
							s = int(cn[0:2],16)
							s_end = 2*s + 2
							name = name + bytes.fromhex(cn[2:s_end]).decode('utf-8')
							cn = cn[s_end:]
							if cn == '':
								break
							name = name + '.'
						break
			name = name.rstrip('.')
			IP_tuple = (IPv6, name)
			IP_list.append(IP_tuple)
			RRR = res[-56:]
			res = res[0:len(res)-56]	
		return IP_list, canonical_list, error, RAA
		
	if QQtype_hex == '000c':		#for type ptr
		ptr_list = []
		query2_hex = QQname + QQtype_hex + QQclass_hex

		message = query1_hex + query2_hex
		response = send_udp_message(message, server, port, timeout)
		if response == None:
			return None, None, None, None
		
		if response[len(message)+4:len(message)+8] == '0006':
			response = message
		Rcode = int(response[7])
		error = error_condition(Rcode)
		res_binary = ''
		for letter in response:
			l = str(bin(int(letter, 16))).lstrip('0b').zfill(4)
			res_binary = res_binary + l
		RAA = res_binary[21]	
		Ranswer = response[len(message):]
		if Ranswer != '':
			while Ranswer != '':
				RRlength = int(Ranswer[20:24],16)
				RRdns_hex = Ranswer[24:((2*RRlength)+24)]
				Rdns = RRdns_hex
				ip = ''
				while Rdns:
					if Rdns[0:2] == 'c0':
						ptr = int(Rdns[2:4],16)
						Rdns = response[ptr*2:]
						while Rdns:
							s = int(Rdns[0:2],16)
							s_end = 2*s + 2
							ip = ip + bytes.fromhex(Rdns[2:s_end]).decode('utf-8')
							Rdns = Rdns[s_end:]
							if Rdns[4:8] == '000c':
								break
							ip = ip + '.'
						break
					s = int(Rdns[0:2],16)
					s_end = 2*s + 2
					ip = ip + bytes.fromhex(Rdns[2:s_end]).decode('utf-8')
					Rdns = Rdns[s_end:]
					ip = ip + '.'
				ip = ip.rstrip('.')
				ip = ip + '.'
				ptr_tuple = (ip, url)
				ptr_list.append(ptr_tuple)
				Ranswer = Ranswer[((2*RRlength)+24):]
		return [], ptr_list, error, RAA
		
	if QQtype_hex == '0001' or QQtype_hex == '0005':		# for query types a and cname
		query2_hex = QQname + '0001' + QQclass_hex		
		message = query1_hex + query2_hex
		response = send_udp_message(message, server, port, timeout)
		
		if response == None:
			return None, None, None, None
		
		res_binary = ''
		for letter in response:
			l = str(bin(int(letter, 16))).lstrip('0b').zfill(4)
			res_binary = res_binary + l
		RID = res_binary[0:16]
		RQR = res_binary[16]
		ROpcode = res_binary[17:21]
		RAA = res_binary[21]
		RTC = res_binary[22]
		RRD = res_binary[23]
		RRA = res_binary[24]
		RZ = res_binary[25:28]
		RRcode = res_binary[28:32]
		RQdcount = res_binary[32:48]
		RAncount = res_binary[48:64]
		RNscount = res_binary[64:80]
		RArcount = res_binary[80:96]
		
		error = ""
		RRcode_int = int(RRcode, 2)
		error = error_condition(RRcode_int)
		
		canonical_list = []
		Ranswers = response[len(message):]
		while Ranswers[4:8] == '0005':
			name_ptr = int(Ranswers[2:4], 16) * 2
			cn = response[name_ptr:]
			name = ''
			if canonical_list != []:
				while cn:
					s = int(cn[0:2],16)
					s_end = 2*s + 2
					name = name + bytes.fromhex(cn[2:s_end]).decode('utf-8')
					cn = cn[s_end:]
					name = name + '.'
					if cn[0:2] == 'c0':
						ptr = int(cn[2:4],16)
						cn = message[ptr*2:(len(message)-10)]
						while cn:
							s = int(cn[0:2],16)
							s_end = 2*s + 2
							name = name + bytes.fromhex(cn[2:s_end]).decode('utf-8')
							cn = cn[s_end:]
							if cn == '':
								break
							name = name + '.'
						break
			name = name.rstrip('.')
			RRlength = int(Ranswers[20:24],16)
			RCname_hex = Ranswers[24:((2*RRlength)+24)]
			cn = RCname_hex
			canonical = ''
			while cn:
				if cn[0:6] == '000001':
					break
				if cn[0:2] == 'c0':
					ptr = int(cn[2:4],16)
					cn = message[ptr*2:(len(message)-10)]
					while cn:
						s = int(cn[0:2],16)
						s_end = 2*s + 2
						canonical = canonical + bytes.fromhex(cn[2:s_end]).decode('utf-8')
						cn = cn[s_end:]
						if cn == '':
							break
						canonical = canonical + '.'
					break
				s = int(cn[0:2],16)
				s_end = 2*s + 2
				canonical = canonical + bytes.fromhex(cn[2:s_end]).decode('utf-8')
				cn = cn[s_end:]
				canonical = canonical + '.'
				
			canonical = canonical.rstrip('.')
			canonical = canonical + '.'
			canonical_tuple = (canonical, name)
			canonical_list.append(canonical_tuple)
			Ranswers = Ranswers[((2*RRlength)+24):]
		res = response
		IP_list = []
		n = int(RAncount, 2) - len(canonical_list)
		for i in range(0, n):
			RRR = res[-32:]
			res = res[0:len(res)-32]
			name_ptr = int(RRR[2:4], 16) * 2
			cn = response[name_ptr:]
			name = ''
			if canonical_list != []:
				while cn:
					s = int(cn[0:2],16)
					s_end = 2*s + 2
					name = name + bytes.fromhex(cn[2:s_end]).decode('utf-8')
					cn = cn[s_end:]
					name = name + '.'
					if cn[0:6] == '000001':
						break
					if cn[0:2] == 'c0':
						ptr = int(cn[2:4],16)
						cn = message[ptr*2:(len(message)-10)]
						while cn:
							s = int(cn[0:2],16)
							s_end = 2*s + 2
							name = name + bytes.fromhex(cn[2:s_end]).decode('utf-8')
							cn = cn[s_end:]
							if cn == '':
								break
							name = name + '.'
						break
			name = name.rstrip('.')
			IP_hex = RRR[-8:]
			IP = str(int(IP_hex[0:2],16)) + '.' + str(int(IP_hex[2:4],16)) + '.' + str(int(IP_hex[4:6],16)) + '.' + str(int(IP_hex[6:],16))
			IP_tuple = (IP, name)
			IP_list.append(IP_tuple)
		if atype == 1:
			return IP_list, canonical_list, error, RAA	

			if QQtype_hex == '0002':		# for type ns
		query2_hex = QQname + QQtype_hex + QQclass_hex
		message = query1_hex + query2_hex
		response = send_udp_message(message, server, port, timeout)

		if response == None:
			return None, None, None, None
		res_binary = ''
		for letter in response:
			l = str(bin(int(letter, 16))).lstrip('0b').zfill(4)
			res_binary = res_binary + l
		RAA = res_binary[21]
		RNscount = int(res_binary[64:80], 2)
		
		Rcode = int(response[7])
		error = error_condition(Rcode)
		
		ns_list = []
		Ranswer = response[len(message):]
		if Ranswer != '':
			while Ranswer != '':
				RRlength = int(Ranswer[20:24],16)
				RRns_hex = Ranswer[24:((2*RRlength)+24)]
				Rns = RRns_hex
				ns = ''
				while Rns:
					if Rns[0:2] == 'c0':
						ptr = int(Rns[2:4],16)
						Rns = response[ptr*2:]
						while Rns:
							if Rns[0:2] == '00':
								break
							if Rns[0:2] == 'c0':
								ptr = int(Rns[2:4],16)
								Rns = response[ptr*2:]
								while Rns:
									if Rns[0:2] == '00':
										break
									s = int(Rns[0:2],16)
									s_end = 2*s + 2
									ns = ns + bytes.fromhex(Rns[2:s_end]).decode('utf-8')
									Rns = Rns[s_end:]
									if Rns[4:8] == '0002':
										break
									ns = ns + '.'
								break
							s = int(Rns[0:2],16)
							s_end = 2*s + 2
							ns = ns + bytes.fromhex(Rns[2:s_end]).decode('utf-8')
							Rns = Rns[s_end:]
							if Rns[4:8] == '0002':
								break
							ns = ns + '.'
						break
					s = int(Rns[0:2],16)
					s_end = 2*s + 2
					ns = ns + bytes.fromhex(Rns[2:s_end]).decode('utf-8')
					Rns = Rns[s_end:]
					ns = ns + '.'
				ns = ns.rstrip('.')
				ns = ns + '.'
				ns_tuple = (ns, url)
				ns_list.append(ns_tuple)
				Ranswer = Ranswer[((2*RRlength)+24):]
		return [], ns_list, error, RAA
		
	if QQtype_hex == '000f':		# for type mx
		query2_hex = QQname + QQtype_hex + QQclass_hex
		message = query1_hex + query2_hex
		response = send_udp_message(message, server, port, timeout)
		if response == None:
			return None, None, None, None
		res_binary = ''
		for letter in response:
			l = str(bin(int(letter, 16))).lstrip('0b').zfill(4)
			res_binary = res_binary + l
		RAA = res_binary[21]
		RNscount = int(res_binary[64:80], 2)
		
		Rcode = int(response[7])
		error = error_condition(Rcode)
		
		mx_list = []
		Ranswer = response[len(message):]
		if Ranswer != '':
			while Ranswer != '':
				RRlength = int(Ranswer[20:24],16)
				RRmx_hex = Ranswer[24:((2*RRlength)+24)]
				Rmx = RRmx_hex
				mx = ''
				num = ''
				while Rmx:
					if Rmx[0:2] == '00':
						if Rmx[2:] == '':
							break
						if Rmx[2:4] == '00':
							num = '0'
							Rmx = Rmx[4:]
						else:
							num = str(int(Rmx[2:4],16))
							Rmx = Rmx[4:]
					if Rmx[0:2] == 'c0':
						ptr = int(Rmx[2:4],16)
						Rmx = response[ptr*2:]
						while Rmx:
							if Rmx[0:2] == '00':
								break
							if Rmx[0:2] == 'c0':
								ptr = int(Rmx[2:4],16)
								Rmx = response[ptr*2:]
								while Rmx:
									if Rmx[0:2] == '00':
										break
									s = int(Rmx[0:2],16)
									s_end = 2*s + 2
									mx = mx + bytes.fromhex(Rmx[2:s_end]).decode('utf-8')
									Rmx = Rmx[s_end:]
									if Rmx[4:8] == '000f':
										break
									mx = mx + '.'
								break
							s = int(Rmx[0:2],16)
							s_end = 2*s + 2
							mx = mx + bytes.fromhex(Rmx[2:s_end]).decode('utf-8')
							Rmx = Rmx[s_end:]
							if Rmx[4:8] == '000f':
								break
							mx = mx + '.'
						break
					s = int(Rmx[0:2],16)
					s_end = 2*s + 2
					mx = mx + bytes.fromhex(Rmx[2:s_end]).decode('utf-8')
					Rmx = Rmx[s_end:]
					mx = mx + '.'
				mx = mx.rstrip('.')
				mx = num + ' ' + mx + '.'
				mx_tuple = (mx, url)
				mx_list.append(mx_tuple)
				Ranswer = Ranswer[((2*RRlength)+24):]
		return [], mx_list, error, RAA
	
		
if len(sys.argv) == 1:
	mode = 0	#interactive
elif sys.argv[1] == '-':
	mode = 0
else:
	mode = 1	#non-interactive
	search_url = ''
	revarg = 0
	qcn = 0
	master = 0
	atype = 0
	command_line = sys.argv[1:]
	print('> python3 mynslookup.py', *command_line)
	for arg in command_line:
		if arg[0] == '-':
			if arg[1:5] == 'port':
				port = int(arg[6:])
			elif arg[1:8] == 'timeout':
				timeout = int(arg[9:])
			elif arg == '-query=ptr' or arg == '-type=ptr':
				query = '000c'
				revarg = 1
			elif arg == '-query=cname' or arg == '-type=cname':
				qcn = 1
			elif arg == '-query=ns' or arg == '-type=ns':
				query = '0002'
			elif arg == '-query=aaaa' or arg == '-type=aaaa':
				query = '001c'
			elif arg == '-query=a' or arg == '-type=a':
				query = '0001'
				atype = 1
			elif arg == '-query=mx' or arg == '-type=mx':
				query = '000f'
			elif arg == '-query=any' or arg == '-type=any':
				master = 1
			else:
				if arg[0:7] == '-query=':
					print("unknown query type: " + arg[7:])
				elif arg[0:6] == '-type=':
					print("unknown query type: " + arg[6:])
				else:
					print("*** Invalid option: " + arg[1:])
		else:
			i = 0
			try:
				temp = ipaddress.ip_address(arg)
			except ValueError:
				i = 1
				if search_url != '':
					dnsserver = arg
					IP_list, canonical_list, error, RAA = find_ip(dnsserver, server, port, timeout, query)
					if IP_list == None and RAA == None:
						print(";; connection timed out; no servers could be reached\n")
						exit()
					server = IP_list[0][0]
					if port == 12000:
						port = 53
				else:
					search_url = arg
			if i == 0:
				if search_url != '':
					server = arg
					if port == 12000:
						port = 53
				else:
					if "." in arg:
						search_url = ".".join((arg.split("."))[::-1]) + ".in-addr.arpa"
					elif ":" in arg:
						temp = ipaddress.ip_address(arg)
						temp = temp.exploded
						temp = (temp.replace(":",""))[::-1]
						s = ''
						for let in temp:
							s = s + let + '.'
						search_url = s + "ip6.arpa"

if mode == 0:						
	qcn = 0
	master = 0
	revarg = 0
	atype = 0

while mode == 0:
	arg = input('> ')
	print(arg)
	if arg == 'exit':
		print("")
		break
	if arg[0:3] == 'set':
		arg = arg.lower()
		if arg[0:11] == 'set timeout':
			timeout = int(arg[12:])
			continue
		elif arg[0:8] == 'set port':
			port = int(arg[9:])
			continue
		elif arg == 'set norecurse' or arg == 'set norec':
			rec = '0'
			continue
		elif arg == 'set recurse' or arg == 'set rec':
			rec = '1'
			continue
		elif arg == 'set type=ptr' or arg == 'set querytype=ptr':
			query = '000c'
			revarg = 1
			qcn = 0
			atype = 0
			continue
		elif arg == 'set type=cname' or arg == 'set querytype=cname':
			qcn = 1
			atype = 0
			revarg = 0
			continue
		elif arg == 'set type=aaaa' or arg == 'set querytype=aaaa':
			query = '001c'
			qcn = 0
			atype = 0
			revarg = 0
			continue
		elif arg == 'set type=a' or arg == 'set querytype=a':
			query = '0001'
			atype = 1
			qcn = 0
			revarg = 0
			continue
		elif arg == 'set type=ns' or arg == 'set querytype=ns':
			query = '0002'
			qcn = 0
			atype = 0
			revarg = 0
			continue
		elif arg == 'set type=mx' or arg == 'set querytype=mx':
			query = '000f'
			qcn = 0
			atype = 0
			revarg = 0
			continue
		elif arg == 'set type=any' or arg == 'set querytype=any':
			master = 1
			qcn = 0
			atype = 0
			revarg = 0
			continue
		elif arg == 'set all':
			if master == 1:
				q = 'ANY'
			elif qcn == 1:
				q = 'CNAME'
			elif atype == 1:
				q = 'A'
			elif query == '0001':
				q = 'A'
			elif query == '000c':
				q = 'PTR'
			elif query == '000f':
				q = 'MX'
			elif query == '0002':
				q = 'NS'
			elif query == '001c':
				q = 'AAAA'
			print("Default server: " + server + "\nAddress: " + server + "#" + str(port))
			print("\nSet options")
			if rec == '1':
				print(" recurse",end = '')
			else:
				print(" norecurse",end = '')
			print("\t\ttimeout = " + str(timeout) + "\t\tport = " + str(port) + "\n querytype = " + q + "\t\tclass = IN")
			continue
		else:
			if arg[0:14] == 'set querytype=':
				print("unknown query type: " + arg[14:])
			elif arg[0:9] == 'set type=':
				print("unknown query type: " + arg[9:])
			else:
				print("*** Invalid option: " + arg[4:])
			continue
			
	if arg[0:6] == 'server':
		if arg[7:].replace(".", "").isnumeric() == False:
			dnsserver = arg[7:]
			IP_list, canonical_list, error, RAA = find_ip(dnsserver, '127.0.0.1', 12000, timeout, query)
			if IP_list == None and RAA == None:
				print(";; connection timed out; no servers could be reached\n")
				continue
			server = IP_list[0][0]
		else:
			server = arg[7:]
		if port == 12000:
			port = 53
		print("Default server: " + server + "\nAddress: " + server + "#" + str(port))
		continue		
	if arg[0:7] == 'lserver':
		if arg[8:].replace(".", "").isnumeric() == False:
			dnsserver = arg[8:]
			IP_list, canonical_list, error, RAA = find_ip(dnsserver, server, port, timeout, query)
			if IP_list == None and RAA == None:
				print(";; connection timed out; no servers could be reached\n")
				continue
			server = IP_list[0][0]
		else:
			server = arg[7:]
		if port == 12000:
			port = 53
		print("Default server: " + server + "\nAddress: " + server + "#" + str(port))
		continue
	else:
		i = 0
		try:
			temp = ipaddress.ip_address(arg)
		except ValueError:
			i = 1
			search_url = arg

		if i == 0:
			if "." in arg:
				search_url = ".".join((arg.split("."))[::-1]) + ".in-addr.arpa"
			elif ":" in arg:
				temp = ipaddress.ip_address(arg)
				temp = temp.exploded
				temp = (temp.replace(":",""))[::-1]
				s = ''
				for let in temp:
					s = s + let + '.'
				search_url = s + "ip6.arpa"
	rev = 0
	
	if master == 1:
		IP_list1, canonical_list1, error1, RAA1 = find_ip(search_url, server, port, timeout, '0001')	#a
		IP_list2, canonical_list2, error2, RAA2 = find_ip(search_url, server, port, timeout, '0002') 	#ns
		IP_list3, canonical_list3, error3, RAA3 = find_ip(search_url, server, port, timeout, '000f')	#mx
		IP_list4, canonical_list4, error4, RAA4 = find_ip(search_url, server, port, timeout, '000c')	#ptr
		 
		if (IP_list1 == None and RAA1 == None) and (IP_list2 == None and RAA2 == None) and (IP_list3 == None and RAA3 == None) and (IP_list4 == None and RAA4 == None):
			print(";; connection timed out; no servers could be reached\n")
			continue
			
		if error1 != 'NOERROR' and error2 != 'NOERROR' and error3 != 'NOERROR' and error4 != 'NOERROR':
			print("** server can't find " + search_url + ":" + error1 + "\n")
			continue
		
		if dnsserver == '':
			print("Server:\t\t" + server)
		else:
			print("Server:\t\t" + dnsserver)
		print("Address:\t" + server + "#" + str(port) + "\n")
		
		if canonical_list4 != []:
			if RAA4 == '0':
				print("Non-authoritive answer:")
			for cname in canonical_list4:
				print(cname[1] + "\tname = " + cname[0])
			if RAA4 == '0':
				print("Authoritive answers can be found from:\n")
			continue
		
		if RAA1 == '0':
			print("Non-authoritive answer:")
		if canonical_list3 != []:
			for cname in canonical_list3:
				print(cname[1] + "\tmail exchanger = " + cname[0])
		if canonical_list1 != []:
			print(search_url,end = '')
			for cname in canonical_list:
				print(cname[1] + "\tcanonical name = " + cname[0])
		if IP_list1 != []:
			for IP in IP_list1:
				if canonical_list1 == []:
					print("Name: " + search_url)
				else:
					print("Name: " + IP[1])
				print("Address: " + IP[0])
		if canonical_list2 != []:
			for cname in canonical_list2:
				print(cname[1] + "\tnameserver = " + cname[0])
		if RAA1 == '0':
			print("\nAuthoritive answers can be found from:\n")
		continue
	
	if (search_url[-13:] == ".in-addr.arpa" or search_url[-9:] == ".ip6.arpa"):
		query = '000c'
		rev = 1
	IP_list, canonical_list, error, RAA = find_ip(search_url, server, port, timeout, query)
	if IP_list == None and RAA == None:
		print(";; connection timed out; no servers could be reached\n")
		continue
	if revarg == 1 or rev == 0:
		if dnsserver == '':
			print("Server:\t\t" + server)
		else:
			print("Server:\t\t" + dnsserver)
		print("Address:\t" + server + "#" + str(port) + "\n")
	if (IP_list == [] and rev == 0 and query != '0002' and query != '000f') or (canonical_list == [] and qcn == 1) or (canonical_list == [] and query == '0002') or (canonical_list == [] and query == '000f'):
		if error == "NOERROR":
			if RAA == '0':
				print("Non-authoritive answer:")
			print("*** Can't find " + search_url + ": No answer\n")
			if RAA == '0':
				print("Authoritive answers can be found from:\n")
		else:
			print("** server can't find " + search_url + ":" + error + "\n")
		continue
	if RAA == '0' and query != '000c':
		print("Non-authoritive answer:")
	if canonical_list != []:
		if query == '0001':
			print(search_url,end = '')
		if qcn == 1:
			print("\tcanonical name = " + canonical_list[0][0])
		for cname in canonical_list:
			if query == '0001' and qcn == 0:
				print(cname[1] + "\tcanonical name = " + cname[0])
			if query == '000c':
				print(cname[1] + "\tname = " + cname[0])
			if query == '0002':
				print(cname[1] + "\tnameserver = " + cname[0])
			if query == '000f':
				print(cname[1] + "\tmail exchanger = " + cname[0])
		if query == '000c' or query == '0002' or query == '000f':
			if RAA == '0':
				print("\nAuthoritive answers can be found from:")
	if qcn == 0:
		for IP in IP_list:
			if canonical_list == []:
				print("Name: " + search_url)
			else:
				print("Name: " + IP[1])
			print("Address: " + IP[0])
		

if mode == 1:
	rev = 0
	if master == 1:
		IP_list1, canonical_list1, error1, RAA1 = find_ip(search_url, server, port, timeout, '0001')	#a
		IP_list2, canonical_list2, error2, RAA2 = find_ip(search_url, server, port, timeout, '0002') 	#ns
		IP_list3, canonical_list3, error3, RAA3 = find_ip(search_url, server, port, timeout, '000f')	#mx
		IP_list4, canonical_list4, error4, RAA4 = find_ip(search_url, server, port, timeout, '000c')	#ptr
		 
		if (IP_list1 == None and RAA1 == None) and (IP_list2 == None and RAA2 == None) and (IP_list3 == None and RAA3 == None) and (IP_list4 == None and RAA4 == None):
			print(";; connection timed out; no servers could be reached\n")
			exit()
			
		if error1 != 'NOERROR' and error2 != 'NOERROR' and error3 != 'NOERROR' and error4 != 'NOERROR':
			print("** server can't find " + search_url + ":" + error1 + "\n")
			exit()
		
		if dnsserver == '':
			print("Server:\t\t" + server)
		else:
			print("Server:\t\t" + dnsserver)
		print("Address:\t" + server + "#" + str(port) + "\n")
		
		if canonical_list4 != []:
			if RAA4 == '0':
				print("Non-authoritive answer:")
			for cname in canonical_list4:
				print(cname[1] + "\tname = " + cname[0])
			if RAA4 == '0':
				print("Authoritive answers can be found from:\n")
			exit()
		
		if RAA1 == '0':
			print("Non-authoritive answer:")
		if canonical_list3 != []:
			for cname in canonical_list3:
				print(cname[1] + "\tmail exchanger = " + cname[0])
		if canonical_list1 != []:
			print(search_url,end = '')
			for cname in canonical_list:
				print(cname[1] + "\tcanonical name = " + cname[0])
		if IP_list1 != []:
			for IP in IP_list1:
				if canonical_list1 == []:
					print("Name: " + search_url)
				else:
					print("Name: " + IP[1])
				print("Address: " + IP[0])
		if canonical_list2 != []:
			for cname in canonical_list2:
				print(cname[1] + "\tnameserver = " + cname[0])
		if RAA1 == '0':
			print("\nAuthoritive answers can be found from:\n")
		exit()
		
	if (search_url[-13:] == ".in-addr.arpa" or search_url[-9:] == ".ip6.arpa"):
		query = '000c'
		rev = 1
	IP_list, canonical_list, error, RAA = find_ip(search_url, server, port, timeout, query)
	if IP_list == None and RAA == None:
		print(";; connection timed out; no servers could be reached\n")
		exit()
	if revarg == 1 or rev == 0:
		if dnsserver == '':
			print("Server:\t\t" + server)
		else:
			print("Server:\t\t" + dnsserver)
		print("Address:\t" + server + "#" + str(port) + "\n")
	if (IP_list == [] and rev == 0 and query != '0002' and query != '000f') or (canonical_list == [] and qcn == 1) or (canonical_list == [] and query == '0002') or (canonical_list == [] and query == '000f'):
		if error == "NOERROR":
			if RAA == '0':
				print("Non-authoritive answer:")
			print("*** Can't find " + search_url + ": No answer\n")
			if RAA == '0':
				print("Authoritive answers can be found from:\n")
		else:
			print("** server can't find " + search_url + ":" + error + "\n")
		exit()
	if RAA == '0' and query != '000c':
		print("Non-authoritive answer:")
	if canonical_list != []:
		if query == '0001':
			print(search_url,end = '')
		if qcn == 1:
			print("\tcanonical name = " + canonical_list[0][0])
		for cname in canonical_list:
			if query == '0001' and qcn == 0:
				print(cname[1] + "\tcanonical name = " + cname[0])
			if query == '000c':
				print(cname[1] + "\tname = " + cname[0])
			if query == '0002':
				print(cname[1] + "\tnameserver = " + cname[0])
			if query == '000f':
				print(cname[1] + "\tmail exchanger = " + cname[0])
		if query == '000c' or query == '0002' or query == '000f' or master == 1:
			if RAA == '0':
				print("\nAuthoritive answers can be found from:")
	if qcn == 0:
		for IP in IP_list:
			if canonical_list == []:
				print("Name: " + search_url)
			else:
				print("Name: " + IP[1])
			print("Address: " + IP[0])
	print("")
"""
https://en.wikipedia.org/wiki/Domain_Name_System
https://linux.die.net/man/1/nslookup
https://en.wikipedia.org/wiki/Nslookup
https://www.geeksforgeeks.org/nslookup-command-in-linux-with-examples/
https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/nslookup
https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1
"""
