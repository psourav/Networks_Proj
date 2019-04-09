#!/usr/bin/python3

# Student name and No.:
# Student name and No.:
# Development platform:
# Python version:
# Version:


from tkinter import *
import sys
import socket

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
hasRegistered = False
hasJoined = False
username = ""
sockfd = ""

def getSocket():
	return sockfd
def makeTCP():
	sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		sockfd.connect( ("localhost", 32340) )
	except socket.error as err:
	 print("Connection error: ", err) 
	 sys.exit(1)
def do_User():
	outstr = "\n[User] username: "+userentry.get()
	CmdWin.insert(1.0, outstr)
	userentry.delete(0, END)
	ename = userentry.get()
	if hasRegistered:
		CmdWin.insert(1.0, "Already Registered")
	else:
		if hasJoined == False:
			username = ename
		else:
			CmdWin.insert(1.0,"Already Joined the Chatroom, Cant Change name")


def do_List():
	CmdWin.insert(1.0, "\nPress List")
	socket = getSocket()
	s="L::\r\n"
	err = socket.send(s.encode("ascii"))
	if err == -1:
		socket.makeTCP()
		socket.send(s.encode("ascii"))

	else:
		plist = socket.recv(32)
		l = plist.decode("ascii")
		listarray = l.split(':')
		if listarray[0] == "G":
			x=listarray.pop(0)
			if x[0] != '':
				for a in x:
					if a != '':
						CmdWin.insert(1.0, "\n" + a)
					else:
						break
			else:
				CmdWin.insert(1.0, "EMPTY")
		else:
			print("error")

def do_Join():
	CmdWin.insert(1.0, "\nPress JOIN")
	if not hasRegistered:
		do_User()
	elif hasJoined:
		#error message
		print("already joined")
	else:
		roomname = userentry.get()
		if roomname:
			userIP, userPort = sockfd.getsockname()
			socket = getSocket()
			err = socket.send("J:%s:%s:%s:%s::\r\n" % (roomname, username, userIP, userPort))
			if err == -1:
				socket = makeTCP()
				socket.send("J:%s:%s:%s:%s::\r\n" % (roomname, username, userIP, userPort))
				
			#get message from server
			s.recv(50)
		else:
			print("Enter chatroom name")



def do_Send():
	CmdWin.insert(1.0, "\nPress Send")


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

def main():
	if len(sys.argv) != 4:
		print("P2PChat.py <server address> <server port no.> <my port no.>")
		sys.exit(2)

	win.mainloop()

if __name__ == "__main__":
	main()

