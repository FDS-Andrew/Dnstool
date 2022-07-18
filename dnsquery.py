from ipwhois.net import Net
from ipwhois.asn import IPASN
import whois
import dns.resolver
import re


class Dnsquery:
    def __init__(self):
        # import variables
        self.query_list = ["A", "AAAA", "NS", "MX", "TXT", "SOA"]
        self.mx_ip = []
        self.domain = []
        self.exchange = []
        self.ip_list = []
        self.ans = 0
        self.mx_name = ''
        self.var = ''
        self.whois = ''

    def mail_list(self):
        # format mail_list
        read = open("mail_list.txt", "r", encoding="utf-8")
        for line in read:
            split = line.split(" ")
            self.domain.extend([split[0]])
            self.exchange.extend([split[1]])
        read.close()

    def mail_ip(self):
        # find mail_server ip
        try:
            a = dns.resolver.resolve(self.mx_name, "A")
            for rdata in a:
                self.mx_ip = self.mx_ip + [rdata]
        except Exception:
            pass

    def enter_domain(self):
        # input domain_name
        self.var = input("\033[1;32;40mEnter domain name\033[0m\n")

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
        except Exception:
            self.ans = 1
            print("\n\033[1;31;40mNo Email Service\033[0m")

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
                print("\033[1;32;40mEmail Exchange Service\033[0m")
                print(self.exchange[num])
                break
            else:
                num += 1

    def whois_mail(self):
        # running whois on mx_ip
        num = 0
        try:
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
        except Exception:
            pass

    def check_ans(self):
        # check if there's an answer, if not run whois_mail
        if self.ans != 1:
            self.whois_mail()
            if self.ans != 1:
                print("\n\033[1;32;40mEmail Exchange Service\033[0m")
                print("\033[1;31;40mNo Email Service in Database \n \033[0m")

    def record_search(self):
        # search for A, AAAA, NS, MX, TXT, SOA
        num = 0
        while num < len(self.query_list):
            print("\n\033[1;32;40m"+self.query_list[num]+" Records \033[0m")
            try:
                record = dns.resolver.resolve(self.var, self.query_list[num])
                for rdata in record:
                    print(rdata)
            except Exception:
                print("\033[1;31;40mNo "+self.query_list[num]+" Records \033[0m")
            num += 1

    def srv_search(self):
        # search for srv records through index
        print("\033[1;32;40mSearching for SRV Records, this may take awhile... \033[0m")
        srv_list = []
        srv_type = ["tcp", "udp", "tls"]
        with open("srvlist.txt", "r", encoding="utf-8") as f:
            for line in f:
                split = line.split()
                srv_list.extend(split)
        count = 0
        ans = 0
        while count < len(srv_type):
            num = 0
            while num < len(srv_list):
                try:
                    record = dns.resolver.resolve("_"+srv_list[num]+"._"+srv_type[count]+"."+self.var, "SRV")
                    for rdata in record:
                        ans = 1
                        print("\033[1;32;40m", srv_type[count], ":\033[0m ", rdata)
                except Exception:
                    pass
                num += 1
            count += 1
        if ans != 1:
            print("\033[1;31;40mNo SRV Records found \033[0m")

    def whois_ns_compare(self):
        # check if whois record is correct
        ans = 0
        try:
            self.whois = str(whois.whois(self.var)).lower()
            print("\n\033[1;32;40mComparing Whois name_server records \033[0m")
            record = dns.resolver.resolve(self.var, "NS")
            for rdata in record:
                pattern = str(rdata)
                if re.search(pattern, self.whois):
                    pass
                else:
                    ans = 1
                    print("\033[1;31;40mWhois name_server records misconfiguration \033[0m")
                    break
            if ans == 0:
                print("Whois name_server records correct")
        except Exception:
            print("\033[1;31;40mNo Whois record for comparison \033[0m")

    def ns_ip_compare(self):
        # check if ns are nested in same ip
        print("\n\033[1;32;40mEvaluating Name_Server IP \033[0m")
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
                print("\033[1;31;40mName_Server nested in same IP \033[0m")
            else:
                print("Name_Server IP configuration correct\n")
        except Exception:
            print("\033[1;31;40mNo NS records to evaluate \033[0m")

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
                print("\033[1;32;40mASN info of \033[0m",ip_list[num])
                print("\033[1;34;40m ASN:\033[0m", results['asn'], '|', "\033[1;34;40mCountry:\033[0m", results['asn_country_code'], '|', "\033[1;34;40mASN registry:\033[0m", results['asn_registry'].upper(), '|', "\033[1;34;40mDescription:\033[0m", results['asn_description'])
                num += 1
        except Exception:
            print("\033[1;31;40mNo ASN records\033[0m")

    def regi_search(self):
        # registrar search
        print("\n\033[1;32;40mRegistrar \033[0m")
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
                    except Exception:
                        ans = 1
                        print(regi.upper())
                        break
            except Exception:
                pass
            num += 1
        if ans != 1:
            print("\033[1;31;40mNo registrar found \n\033[0m")

    def exp_date(self):
        # expiration date
        print("\033[1;32;40mExpiration date \033[0m")
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
                    except Exception:
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
            except Exception:
                pass
            num += 1
        if ans != 1:
            print("\033[1;31;40mNo Expiration date found \033[0m")


class Steps:
    def search(self):
        run = Dnsquery()
        run.mail_list()
        run.enter_domain()
        run.record_search()
        run.whois_ns_compare()
        run.ns_ip_compare()
        run.as_search()
        run.regi_search()
        run.exp_date()
        run.mx_name_search()
        run.mail_ip()
        run.compare()
        run.check_ans()
        run.srv_search()


call_function = Steps()
call_function.search()
