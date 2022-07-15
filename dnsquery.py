import whois
import dns.resolver
import re


class Search:
    def __init__(self):
        # import variables
        self.query_list = ["A", "AAAA", "NS", "MX", "TXT", "SOA"]
        self.mx_ip = []
        self.domain = []
        self.exchange = []
        self.ans = 0
        self.mx_name = ''
        self.var = ''

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
        self.var = input("\033[1;32;40mEnter domain name \n \033[0m")

    def mx_name_search(self):
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
                print("\n\033[1;32;40mEmail Exchange Service\033[0m")
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

    def ns_compare(self):
        ans = 0
        try:
            w = str(whois.whois(self.var)).lower()
            print("\n\033[1;32;40mComparing Whois name_server records \033[0m")
            record = dns.resolver.resolve(self.var, "NS")
            for rdata in record:
                pattern = str(rdata)
                if re.search(pattern, w):
                    pass
                else:
                    ans = 1
                    print("\033[1;31;40mWhois name_server records misconfiguration \033[0m")
                    break
            if ans == 0:
                print("Whois name_server records correct")
        except Exception:
            print("\033[1;31;40mNo Whois record for comparison \033[0m")


class Steps:
    def __init__(self):
        run = Search()
        run.mail_list()
        run.enter_domain()
        run.record_search()
        run.ns_compare()
        run.mx_name_search()
        run.mail_ip()
        run.compare()
        run.check_ans()


call_function = Steps()
