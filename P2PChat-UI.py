#!/usr/bin/python3

# Student name and No.:
# Student name and No.:
# Development platform:
# Python version:
# Version:


from tkinter import *
import sys
import socket
import time
import threading
#
# Global variables
#



#
# This is the hash function for generating a unique
# Hash ID for each peer.
# Source: http://www.cse.yorku.ca/~oz/hash.html
#
# Concatenate the peer's username, str(IP address), 
# and str(Port) to form a string that be the input 
# to this hash function
#
def sdbm_hash(instr):
	hash = 0
	for c in instr:
		hash = int(ord(c)) + (hash << 6) + (hash << 16) - hash
	return hash & 0xffffffffffffffff


#
# Functions to handle user input
#



hasJoined = False

username = ""

roomname = ""

hasRegistered = False
oHID = "" 
msgID ="" 

sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sockfd.connect( ("localhost", 32340) )

gList = {}
def getSocket():
	return sockfd

def setSocket(sock):
	sockfd = sock

def makeTCP(userIP, userPort):
	sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		sockfd.connect( (userIP, userPort) )
	except :
		print("Connection error: ", err)
		sys.exit(1)

	return sockfd

def do_User():
	global hasRegistered, username
	
	if hasRegistered.get():
		CmdWin.insert(1.0, "\nAlready Registered")
	else:
		if hasJoined.get() == False:
			if userentry.get():
				username=userentry.get()
				outstr = "\n[User] username: "+userentry.get()
				CmdWin.insert(1.0, outstr)
				userentry.delete(0, END)
				hasRegistered=True
			else: 
				CmdWin.insert(1.0,"Input User Name")


		else:
			CmdWin.insert(1.0,"Already Joined the Chatroom, Cant Change name")


def do_List():
	
	sockfd = getSocket()
	s = "L::\r\n"
	try : sockfd.send(s.encode("ascii"))
	except:
		sockfd.makeTCP()
		sockfd.send(s.encode("ascii"))

	plist = sockfd.recv(32)
	l = plist.decode("ascii")
	listarray = l.split(':')
	if listarray[0] == "G":
		print(listarray)
		if listarray[1] != "":
			for a in listarray:
				if a != "G":
					if a != "":
						CmdWin.insert(1.0, "\n" + a)
					else:
						break 
		else:
			CmdWin.insert(1.0, "\nEMPTY")
	else:
		CmdWin.insert(1.0, "ERROR")


def establishForwardLink(hashVal, memberList , memberListHash):
	memberListHash = memberListHash.sort()
	start = memberListHash.index(hashVal) + 1

	while gList[start]["hash"] != hashVal:
		if  gList[start]["hash"] in gList[start-1]["backwardLink"]:
			start = (start + 1) % len(memberListHash) #(i.e., wrap around if reaching the end)
		else
			establish a TCP connection to the member at gList[start] 
			
			sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

			IP = memberList[memberListHash[start]][1]
			Port = memberList[memberListHash[start]][2]
			
			try: sockfd.connect( (IP, Port) )
			except:
				start = (start + 1) % len(memberListHash)
				continue

			userIP, userPort = sockfd.getsockname()

			msg = "P:%s:%s:%s:%s::\r\n" % (roomname, username, userIP, userPort)

			makeTCP(userIP, userPort)
			if successful
				declare successfully FORWARD LINKED 
				add this connection to H’s socket list 
				update gList to indicate this link
				jump out of the while loop
			else
				start = (start + 1) % gList.size
				goto step 5
			
				
		if failure to establish a forward link
			report error and schedule to retry the above logic later

def getMemberList(arr):
	global gList
	print(arr)
	i = 1
	hash = arr[i]
	memberListHash = []
	memberList = {}
	j = 0
	while arr[i+1] != '':
		hashedVal = sdbm_hash(arr[i+1] + arr[i+2] + arr[i+3])
		memberListHash.append(hashedVal)
		memberList[hashedVal] = (arr[i+1] , arr[i+2] , arr[i+3])
		gList[j] = {"username": arr[i+1] , "userIP":arr[i+2] , "userPort":arr[i+3], "hash" : hashedVal ,"forwardLink" : [], "backwardLink" : []}
		j+=1
		i+=3
	return memberList, memberListHash

def JoinRoom():
	global roomname, username, sockfd
	sockfd = getSocket()
	userIP, userPort = sockfd.getsockname()
	msg = "J:%s:%s:%s:%s::\r\n" % (roomname, username, userIP, userPort)
	print(msg)
	hashVal = sdbm_hash(str(username) + str(userIP) + str(userPort))
	try:
		sockfd.send(msg.encode("ascii"))
	except:
		sockfd = makeTCP("localhost", 32340)
		setSocket(sockfd)
		sockfd.send(msg.encode("ascii"))
		
	#get message from server
	packet = ""
	arr = packet.split(':')
	
	while arr[-1] != '\r\n':
		packet += sockfd.recv(2).decode("ascii")
		arr = packet.split(':')

	return arr, hashVal

def do_Join():
	global hasRegistered, hasJoined, roomname, sockfd
	CmdWin.insert(1.0, "\nPress JOIN")
	print(hasRegistered)
	if not hasRegistered:
		do_User()
	elif hasJoined:
		#error message
		print("already joined")
	else:
		roomname = userentry.get()
		arr,hashVal = JoinRoom()
		memberList, memberListHash = getMemberList(arr)
		print(memberListHash)
		if len(memberListHash) > 1 :
			print("connect to someone")
			establishForwardLink(hashVal, memberList , memberListHash)
		else :
			print("no need for connection")

		hasJoined = True





def do_Send():
	global roomname, oHID, username, msgID
	msg = userentry.get()
	if msg = "":
		CmdWin.insert(1.0, "\nBlank Input")
		return
	prot = "T:%s:%d:%s:%d:%d:%s::\r\n" % (roomname,oHID , username, msgID, len(msg), msg )

	if hasJoined==False:
		CmdWin.insert(1.0, "\nNot Connected to any Chatroom")
		return

	socket = getSocket()

	try:
		socket.send(prot.encode("ascii"))
		print("Send via Forward Link\n")

	except socket.error as err:
		print("Send, forward err ->", err)

def do_Poke():
	CmdWin.insert(1.0, "\nPress Poke")


def do_Quit():
	CmdWin.insert(1.0, "\nPress Quit")
	sys.exit(0)


#
# Set up of Basic UI
#
win = Tk()

win.title("MyP2PChat")

#Top Frame for Message display
topframe = Frame(win, relief=RAISED, borderwidth=1)
topframe.pack(fill=BOTH, expand=True)
topscroll = Scrollbar(topframe)
MsgWin = Text(topframe, height='15', padx=5, pady=5, fg="red", exportselection=0, insertofftime=0)
MsgWin.pack(side=LEFT, fill=BOTH, expand=True)
topscroll.pack(side=RIGHT, fill=Y, expand=True)
MsgWin.config(yscrollcommand=topscroll.set)
topscroll.config(command=MsgWin.yview)

#Top Middle Frame for buttons
topmidframe = Frame(win, relief=RAISED, borderwidth=1)
topmidframe.pack(fill=X, expand=True)
Butt01 = Button(topmidframe, width='6', relief=RAISED, text="User", command=do_User)
Butt01.pack(side=LEFT, padx=8, pady=8);
Butt02 = Button(topmidframe, width='6', relief=RAISED, text="List", command=do_List)
Butt02.pack(side=LEFT, padx=8, pady=8);
Butt03 = Button(topmidframe, width='6', relief=RAISED, text="Join", command=do_Join)
Butt03.pack(side=LEFT, padx=8, pady=8);
Butt04 = Button(topmidframe, width='6', relief=RAISED, text="Send", command=do_Send)
Butt04.pack(side=LEFT, padx=8, pady=8);
Butt06 = Button(topmidframe, width='6', relief=RAISED, text="Poke", command=do_Poke)
Butt06.pack(side=LEFT, padx=8, pady=8);
Butt05 = Button(topmidframe, width='6', relief=RAISED, text="Quit", command=do_Quit)
Butt05.pack(side=LEFT, padx=8, pady=8);

#Lower Middle Frame for User input
lowmidframe = Frame(win, relief=RAISED, borderwidth=1)
lowmidframe.pack(fill=X, expand=True)
userentry = Entry(lowmidframe, fg="blue")
userentry.pack(fill=X, padx=4, pady=4, expand=True)

#Bottom Frame for displaying action info
bottframe = Frame(win, relief=RAISED, borderwidth=1)
bottframe.pack(fill=BOTH, expand=True)
bottscroll = Scrollbar(bottframe)
CmdWin = Text(bottframe, height='15', padx=5, pady=5, exportselection=0, insertofftime=0)
CmdWin.pack(side=LEFT, fill=BOTH, expand=True)
bottscroll.pack(side=RIGHT, fill=Y, expand=True)
CmdWin.config(yscrollcommand=bottscroll.set)
bottscroll.config(command=CmdWin.yview)


#KEEP ALIVE PROCEDURE
def thd_func():
	starttime=time.time()
	while True:
		if ((time.time() - starttime) % 20.0) == 0 and hasJoined:
			JoinRoom()

newthd = threading.Thread(target=thd_func, args=())
newthd.start()



def main():
	if len(sys.argv) != 4:
		print("P2PChat.py <server address> <server port no.> <my port no.>")
		sys.exit(2)

	win.mainloop()

if __name__ == "__main__":
	main()

