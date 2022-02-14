"""
DNS Server 
"""

import os
import sys
from socket import *
import struct
import binascii
import time
import pickle

with open ('cache.txt', 'rb') as fp:
	itemlist = pickle.load(fp)

newlist = itemlist

if itemlist != []:
	for item in itemlist:
		current = time.time()
		if current > item[3] + item[2]:
			newlist.remove(item)

with open('cache.txt', 'wb') as fp:
	pickle.dump(newlist, fp)

port = 12000
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
serverSocket.bind(('', port))
while True:
	with open ('cache.txt', 'rb') as fp:
		newlist = pickle.load(fp)
	msg, clientAddress = serverSocket.recvfrom(2048)
	start = time.time()
	tim, _ = serverSocket.recvfrom(1024)
	timeout = int(tim.decode())
	message = binascii.hexlify(msg).decode("utf-8")
	
	data = ''
	if newlist != []:
		for item in newlist:
			if item[0] == message:
				current = time.time()
				if current < item[3] + item[2]:
					data = binascii.unhexlify(item[1])
					print("from cache")
					break
				newlist.remove(item)
	
	flag = 0
	if data == '':	
		clientsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		clientsocket.settimeout(timeout)
		try:
			clientsocket.sendto(binascii.unhexlify(message), ('8.8.8.8', 53))
			data, _ = clientsocket.recvfrom(4096)
		except socket.timeout:
			continue
		finally:
			clientsocket.close()
		flag = 1
		print("from server")
	
	serverSocket.sendto(data, clientAddress)
	response = binascii.hexlify(data).decode("utf-8")
	
	if flag == 1:
		if len(response) != len(message) and message[-8:-4] != '000c':
			ttl_list = []
			res = response[len(message):]
			while res:
				RRlength = int(res[20:24],16)
				Answer = res[0:((2*RRlength)+24)]
				timetolive = int(Answer[12:20],16)
				ttl_list.append(timetolive)
				res = res[((2*RRlength)+24):]
			ttl = min(ttl_list)
			timestamp = time.time()
			element = (message, response, ttl, timestamp)
			newlist.append(element)

	with open('cache.txt', 'wb') as fp:
		pickle.dump(newlist, fp)
		
	end = time.time()
	print(end-start)
		
