import dns.resolver
import whois

''' enter domain name '''
var = input("\033[1;32;40mEnter domain name \n \033[0m")
m = dns.resolver.resolve(var, 'MX')
mxlist = []
preflist = []
MX = []
pref = []
mxip = []
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

''' mail exchange domain '''
for rdata in m:
        MX = [rdata.exchange]
        pref = [rdata.preference]
        mxlist.extend(MX)
        preflist.extend(pref)
mxnm = str(mxlist[(preflist.index(min(preflist)))])

''' mail server ip '''
a = dns.resolver.resolve(mxnm, "A")
for rdata in a:
        mxip = [rdata]

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
f.close()

if ANSWR == 0:
        num = 0
        for rdata in a:
                w = str(whois.whois(str(mxip[num])))
                f = open("whois.txt", "w")
                f.write(w)
                f.close()
                f = open("whois.txt", "r")
                lines = f.readlines()
                x = open("maillist.txt", "r")
                count = 0
                for line in x:
                        if domain[count] in lines[1].lower():
                                print("\n\033[1;32;40mMail Exchange Service \n \033[0m")
                                print(exchange[count])
                                break
                        else:
                                count += 1
                else:
                        continue
                break
                num += 1
