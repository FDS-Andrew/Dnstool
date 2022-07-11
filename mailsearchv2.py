import re
import dns.resolver


var = input("\033[1;32;40mEnter domain name \n \033[0m")
m = dns.resolver.resolve(var, 'MX')
mxlist = []
preflist = []
ANSWR = 0

''' load maillist '''
domain = []
exchange = []
f = open("maillist.txt", "r")
for line in f:
    test = line.split(" ")
    domain.extend([test[0]])
    exchange.extend([test[1]])	
f.close()

def mailsearch():
	''' mail exchange domain '''
	for rdata in m:
		MX = [rdata.exchange]
		pref = [rdata.preference]
		mxlist.extend(MX)
		preflist.extend(pref)
	mxnm = str(mxlist[(preflist.index(min(preflist)))])

	''' compare '''
	num = 0
	f = open("maillist.txt", "r")
	for line in f:
		if domain[num] in mxnm :
			ANSWR = 1
			print("\n\033[1;32;40mMail Exchange Service \n \033[0m") 
			print(exchange[num])
			break
		else:
			num = num + 1
			ANSWR = 0
	f.close()
	
mailsearch()
if ANSWR == 0:
	print("No mail exchange service")



