import os
import sys

class SecurityError(Exception):
	pass

def getuser():
	uid=str(os.getuid())
	f=open("/etc/passwd", "r")
	for line in f:
		col=line.split(":")
		if len(col)>2 and col[2]==uid:
			f.close()
			return col[0]
	f.close()
	return ""

def user_exist(username):
	f=open("/etc/passwd", "r")
	for line in f:
		if line.split(":")[0]==username:
			f.close()
			return True
	f.close()
	return False

def read_delegates(config):
	path=config["paths"]["delegation_file"]
	names=[]
	if not os.path.isfile(path):
		return names
	try:
		f=open(path,"r")
	except OSError:
		raise SecurityError("Can't read delegation list: %s" %path)
	for line in f:
		name=line.strip()
		if name !="":
			names.append(name)
	f.close()
	return names

def write_delegates(names, config):
	path=config["paths"]["delegation_file"]
	try:
		f=open(path,"w")
	except OSError:
		raise SecurityError("Can't save delegation list: %s" %path)
	for name in names:
		f.write(name+"\n")
	f.close()


def check_identity(config):
	user=getuser()
	x=config["general"]["authorized_user"]
	if user==x:
		return
	if user in read_delegates(config):
		return
	raise SecurityError("Account '%s 'is not authorized." %user)

def add_delegate(username, config):
	x=config["general"]["authorized_user"]
	if getuser()!=x:
		raise SecurityError("Only '%s' can manage delegated users."%primary)
	if username=="root" or username==x:
		raise SecurityError("Can't delegate to '%s'."%username)
	if not user_exist(username):
		raise SecurityError("Local Linux account '%s' doesn't exist."%username)
	names=read_delegates(config)
	if username not in names:
		names.append(username)
		write_delegates(names,config)

def remove_delegate(username, config):
	x=config["general"]["authorized_user"]
	if getuser()!=x:
		raise SecurityError("Only '%s' can manage delegated users. "%x)
	names=read_delegates(config)
	if username not in names:
		raise SecurityError("'%s' is not a delegated user."%username)	
	new_names=[]
	for name in names:
		if name!=username:
			new_names.append(name)
	write_delegates(new_names,config)

def list_delegates(config):
	x=config["general"]["authorized_user"]
	if getuser()!=x:
		raise SecurityError("Only '%s' can manage delegated users. "%x)
	return read_delegates(config)
























