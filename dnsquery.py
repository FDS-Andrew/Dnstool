from ipwhois.net import Net
from ipwhois.asn import IPASN
import threading
import whois
import dns.resolver
import re


class Dnsquery:
    # import variables
    query_list = ["A", "AAAA", "NS", "MX", "TXT", "SOA"]
    mx_ip = []
    domain = []
    exchange = []
    ip_list = []
    srv_list = []
    ans = 0
    error = 0
    G = "\033[1;32;40m"
    R = "\033[1;31;40m"
    Y = "\033[1;33;40m"
    N = "\033[0m"
    mx_name = ''
    var = ''
    whois = ''

    def mail_ip(self):
        # find mail_server ip
        try:
            a = dns.resolver.resolve(self.mx_name, "A")
            for rdata in a:
                self.mx_ip = self.mx_ip + [rdata]
        except dns.resolver.NoAnswer:
            pass

    def enter_domain(self):
        # input domain_name
        self.var = input(self.G+"Enter domain name"+self.N+"\n")

    def mx_name_search(self):
        # choosing the mail_server with the highest priority
        try:
            m = dns.resolver.resolve(self.var, self.query_list[3])
            mx_list = []
            pref_list = []
            for rdata in m:
                mx = [rdata.exchange]
                pref = [rdata.preference]
                mx_list.extend(mx)
                pref_list.extend(pref)
            self.mx_name = str(mx_list[(pref_list.index(min(pref_list)))])
        except dns.resolver.NoAnswer:
            self.ans = 1
            print(self.R+"\nNo Email Service"+self.N)

    def compare(self):
        # compare mx_name with mail_list
        with open("mail_list.txt", "r", encoding="utf-8") as file_path:
            for count, line in enumerate(file_path):
                pass
        count += 1
        num = 0
        while num < count:
            if self.domain[num] in self.mx_name:
                self.ans = 1
                print(self.G+"Email Exchange Service"+self.N)
                print(self.exchange[num])
                break
            else:
                num += 1

    def whois_mail(self):
        # running whois on mx_ip
        num = 0
        while num < len(self.mx_ip):
            w = str(whois.whois(str(self.mx_ip[num])))
            with open("whois.txt", "w", encoding="utf-8") as blank:
                blank.write(w)
            with open("whois.txt", "r", encoding="utf-8") as read:
                lines = read.readlines()
                self.mx_name = lines[1].lower()
                self.compare()
            if self.ans == 1:
                break
            else:
                num += 1

    def record_search(self):
        # search for A, AAAA, NS, MX, TXT, SOA
        for num in range(len(self.query_list)):
            try:
                record = dns.resolver.resolve(self.var, self.query_list[num])
                print("\n"+self.G+self.query_list[num]+" Records"+self.N)
                for rdata in record:
                    print(rdata)
            except dns.resolver.NoAnswer:
                print(self.R+"\nNo "+self.query_list[num]+" Records"+self.N)
            except dns.resolver.NoNameservers:
                self.error = 1
                break
            except dns.resolver.NXDOMAIN:
                self.error = 1
                break

    def list(self):
        # format srv_list
        with open("srvlist.txt", "r", encoding="utf-8") as f:
            for line in f:
                split = line.split()
                self.srv_list.extend(split)
        # format mail_list
        with open("mail_list.txt", "r", encoding="utf-8") as read:
            for line in read:
                split = line.split(" ")
                self.domain.extend([split[0]])
                self.exchange.extend([split[1]])

    def srv_tcp(self):
        # search for srv records with tcp
        for n in range(len(self.srv_list)):
            try:
                record = dns.resolver.resolve("_"+self.srv_list[n]+"._tcp."+self.var, "SRV")
                for data in record:
                    print(self.Y+"TCP:"+self.N, data)
            except dns.resolver.NXDOMAIN:
                pass

    def srv_tls(self):
        # search for srv records with tls
        for n in range(len(self.srv_list)):
            try:
                record = dns.resolver.resolve("_"+self.srv_list[n]+"._tls."+self.var, "SRV")
                for data in record:
                    print(self.Y+"TLS:"+self.N, data)
            except dns.resolver.NXDOMAIN:
                pass

    def srv_udp(self):
        # search for srv records with udp
        for n in range(len(self.srv_list)):
            try:
                record = dns.resolver.resolve("_"+self.srv_list[n]+"._udp."+self.var, "SRV")
                for data in record:
                    print(self.Y+"UDP:"+self.N, data)
            except dns.resolver.NXDOMAIN:
                pass

    def whois_ns_compare(self):
        # check if whois record is correct
        ans = 0
        self.whois = str(whois.whois(self.var)).lower()
        print(self.G+"\nComparing Whois name_server records"+self.N)
        record = dns.resolver.resolve(self.var, "NS")
        for rdata in record:
            pattern = str(rdata)
            if re.search(pattern, self.whois):
                pass
            else:
                ans = 1
                print(self.R+"Whois name_server records misconfiguration"+self.N)
                break
        if ans == 0:
            print(self.Y+"Whois name_server records correct"+self.N)

    def ns_ip_compare(self):
        # check if ns are nested in same ip
        print(self.G+"\nEvaluating Name_Server IP"+self.N)
        try:
            ns = dns.resolver.resolve(self.var, "NS")
            num = 0
            ip_set = set()
            for ns_data in ns:
                name = str(ns_data)
                a = dns.resolver.resolve(name, "A")
                for a_data in a:
                    string = re.sub(r".\d+$", "", str(a_data))
                    ip_set.add(string)
                    num += 1
            if len(ip_set) != num:
                print(self.R+"Name_Server nested in same IP\n"+self.N)
            else:
                print(self.Y+"Name_Server IP configuration correct\n"+self.N)
        except dns.resolver.NoAnswer:
            print(self.R+"No NS records to evaluate"+self.N)

    def as_search(self):
        # ASN info search
        ip_list = set()
        try:
            ns = dns.resolver.resolve(self.var, "NS")
            for ns_data in ns:
                name = str(ns_data)
                a = dns.resolver.resolve(name, "A")
                for a_data in a:
                    ip_list.add(str(a_data))
            ip_list = list(ip_list)
            num = 0
            while num < len(ip_list):
                net = Net(ip_list[num])
                obj = IPASN(net)
                results = obj.lookup()
                print(self.G+"ASN info of "+self.N, ip_list[num])
                print(self.Y+" ASN:"+self.N, results['asn'], '|', self.Y+"Country:"+self.N, results['asn_country_code'], '|', self.Y+"ASN registry:"+self.N, results['asn_registry'].upper(), '|', self.Y+"Description:"+self.N, results['asn_description'])
                num += 1
        except dns.resolver.NoAnswer:
            print(self.R+"\nNo ASN records"+self.N)

    def regi_search(self):
        # registrar search
        print(self.G+"\nRegistrar "+self.N)
        with open("whois.txt", "w", encoding="utf-8") as f:
            f.write(self.whois)
        with open("whois.txt", "r", encoding="utf-8") as f:
            lines = f.readlines()
            num = 0
            ans = 0
        while num < len(lines):
            try:
                x = re.search(r"\bregistrar\b", (lines[num])).groups()
                if x == ():
                    regi = re.sub(r'( "registrar": )', '', lines[num])
                    regi = re.sub(r",", '', regi)
                    try:
                        re.search("null", regi).groups()
                        break
                    except AttributeError:
                        ans = 1
                        print(regi.upper())
                        break
            except AttributeError:
                pass
            num += 1
        if ans != 1:
            print(self.R+"No registrar found \n"+self.N)

    def exp_date(self):
        # expiration date
        print(self.G+"Expiration date "+self.N)
        with open("whois.txt", "r", encoding="utf-8") as f:
            lines = f.readlines()
            num = 0
            ans = 0
        while num < len(lines):
            try:
                x = re.search(r"\bexpiration_date\b", (lines[num])).groups()
                if x == ():
                    exp = re.sub(r'( "expiration_date": )', '', lines[num])
                    exp = re.sub(r",", '', exp)
                    try:
                        re.search("null", exp).groups()
                        break
                    except AttributeError:
                        ans = 1
                    if "[" in exp:
                        num += 1
                        exp = re.sub(r'^\s*', '', lines[num])
                        exp = re.sub(r",", '', exp)
                        print(exp)
                        break
                    else:
                        print(exp)
                        break
            except AttributeError:
                pass
            num += 1
        if ans != 1:
            print(self.R+"No Expiration date found "+self.N)


class Steps:
    def __init__(self):
        run = Dnsquery()
        run.enter_domain()
        run.list()
        run.record_search()
        if run.error != 1:
            run.whois_ns_compare()
            run.ns_ip_compare()
            run.as_search()
            run.regi_search()
            run.exp_date()
            run.mx_name_search()
            run.mail_ip()
            run.compare()
            if run.ans != 1:
                run.whois_mail()
                if run.ans != 1:
                    print(run.G+"\nEmail Exchange Service"+run.N)
                    print(run.R+"No Email Service in Database\n"+run.N)
            if run.error == 1:
                pass
            else:
                print(run.G+"Brute forcing SRV Records, this may take awhile..."+run.N)
                if __name__ == "__main__":
                    p1 = threading.Thread(target=run.srv_tcp)
                    p1.start()
                    p2 = threading.Thread(target=run.srv_tls)
                    p2.start()
                    p3 = threading.Thread(target=run.srv_udp)
                    p3.start()
                    p1.join()
                    p2.join()
                    p3.join()
        else:
            print(run.R+"\nDomain does not exist"+run.N)


call_function = Steps()
