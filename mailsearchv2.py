import whois
import dns.resolver


class MailSearch:
    def __init__(self):
        # import variables
        self.mx_ip = []
        self.domain = []
        self.exchange = []
        self.ans = 0
        self.mx_name = ''

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
        a = dns.resolver.resolve(self.mx_name, "A")
        for rdata in a:
            self.mx_ip = self.mx_ip + [rdata]

    def enter_domain(self):
        # input domain_name
        var = input("\033[1;32;40mEnter domain name \n \033[0m")
        m = dns.resolver.resolve(var, 'MX')
        mx_list = []
        pref_list = []
        for rdata in m:
            mx = [rdata.exchange]
            pref = [rdata.preference]
            mx_list.extend(mx)
            pref_list.extend(pref)
        self.mx_name = str(mx_list[(pref_list.index(min(pref_list)))])

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
                print("\n\033[1;32;40mMail Exchange Service \n \033[0m")
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

    def check_ans(self):
        # check if there's an answer, if not run whois_mail
        if self.ans != 1:
            self.whois_mail()


run = MailSearch()
run.mail_list()
run.enter_domain()
run.mail_ip()
run.compare()
run.check_ans()
