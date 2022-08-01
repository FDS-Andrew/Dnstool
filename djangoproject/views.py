from django.shortcuts import render
from django.http import HttpResponse
from django.template import loader
from ipwhois.net import Net
from ipwhois.asn import IPASN
import sys
import threading
import whois
import dns.zone
import dns.resolver
import dns.reversename
import re

# Create your views here.
def index(request):
    template = loader.get_template('home.html')
    context = {}
    return HttpResponse(template.render(context, request))
def search(request):
    domain = request.POST["domain"]
    template = loader.get_template('ans.html')

    def record_search(type):
        try:
            if type == "a":
                a = dns.resolver.resolve(domain, "A")
                a_data = []
                for data in a:
                    a_data.append(str(data))
                return a_data
            if type == "aaaa":
                aaaa = dns.resolver.resolve(domain, "AAAA")
                aaaa_data = []
                for data in aaaa:
                    aaaa_data.append(str(data))
                return aaaa_data
            if type == "ns":
                ns = dns.resolver.resolve(domain, "NS")
                ns_data = []
                for data in ns:
                    ns_data.append(str(data))
                return ns_data
            if type == "mx":
                mx = dns.resolver.resolve(domain, "MX")
                mx_data = []
                for data in mx:
                    mx_data.append(str(data))
                return mx_data
            if type == "txt":
                txt = dns.resolver.resolve(domain, "TXT")
                txt_data = []
                for data in txt:
                    txt_data.append(str(data))
                return txt_data
            if type == "soa":
                soa = dns.resolver.resolve(domain, "SOA")
                soa_data = []
                for data in soa:
                    soa_data.append(str(data))
                return soa_data
        except Exception:
            return "none"

    def whois_ns_compare():
        error = "false"
        w = str(whois.whois(domain)).lower()
        try:
            record = dns.resolver.resolve(domain, "NS")
            for data in record:
                pattern = str(data)
                if re.search(pattern, w):
                    pass
                else:
                    error = "true"
                    return "misconfigured"
                    break
        except Exception:
            return "misconfigured"
        if error == "false":
            return "correct"

    def ns_ip_compare():
        try:
            ns = dns.resolver.resolve(domain, "NS")
            ip_num = 0
            ip_set = set()
            for ns_data in ns:
                name = str(ns_data)
                a = dns.resolver.resolve(name, "A")
                for a_data in a:
                    string = re.sub(r".\d+$", "", str(a_data))
                    ip_set.add(string)
                    ip_num += 1
            if len(ip_set) != ip_num:
                return "misconfigured"
            else:
                return "correct"
        except Exception:
            return "none"

    def as_search(type):
        ip_list = set()
        asn_list = []
        country = []
        registry = []
        description = []
        try:
            ns = dns.resolver.resolve(domain, "NS")
            for ns_data in ns:
                name = str(ns_data)
                a = dns.resolver.resolve(name, "A")
                for a_data in a:
                    ip_list.add(str(a_data))
            ip_list = list(ip_list)
            for num in range(len(ip_list)):
                net = Net(ip_list[num])
                obj = IPASN(net)
                results = obj.lookup()
                asn_list.append("ASN of "+ip_list[num]+" : "+results['asn'])
                country.append("Country of "+ip_list[num]+" : "+results['asn_country_code'])
                registry.append("Registry of "+ip_list[num]+" : "+results['asn_registry'])
                description.append("Description of "+ip_list[num]+" : "+results['asn_description'])
        except dns.resolver.NoAnswer:
            return "none"
        if type == "asn":
            return asn_list
        if type == "country":
            return country
        if type == "registry":
            return registry
        if type == "description":
            return description

    def regi_search():
        w = str(whois.whois(domain))
        with open("whois.txt", "w", encoding="utf-8") as f:
            f.write(w)
        with open("whois.txt", "r", encoding="utf-8") as f:
            lines = f.readlines()
            ans = 0
        for num in range(len(lines)):
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
                        return regi.upper()
                        break
            except AttributeError:
                pass
        if ans != 1:
            return "none"

    def exp_date():
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
                        return exp
                        break
                    else:
                        return exp
                        break
            except AttributeError:
                pass
            num += 1
        if ans != 1:
            return "none"

    def o365check(type):
        if type == "auto":
            try:
                cname = dns.resolver.resolve("autodiscover."+domain, "CNAME")
                for data in cname:
                    if re.search(r"autodiscover.outlook.com", str(data)):
                        return "correct"
                    else:
                        return "misconfigured"
            except Exception:
                return "misconfigured"
        if type == "msoid":
            try:
                cname = dns.resolver.resolve("msoid."+domain, "CNAME")
                for data in cname:
                    if re.search(r"clientconfig.microsoftonline-p.net", str(data)):
                        return "correct"
                    else:
                        pass
            except Exception:
                pass
        if type == "lync":
            try:
                cname = dns.resolver.resolve("lyncdiscover."+domain, "CNAME")
                for data in cname:
                    if re.search(r"webdir.online.lync.com", str(data)):
                        return "correct"
                    else:
                        pass
            except Exception:
                pass
        if type == "365mx":
            try:
                ans = 0
                mx = dns.resolver.resolve(domain, "MX")
                for data in mx:
                    if re.search(r"mail.protection.outlook.com", str(data)):
                        return "correct"
                        ans = 1
                        break
                    elif re.search(r"protection.outlook.com", str(data)):
                        return "update"
                        ans = 1
                        break
                    else:
                        pass
                if ans != 1:
                    return "misconfigured"
            except Exception:
                return "misconfigured"
        if type == "spf":
            try:
                ans = 0
                spf = dns.resolver.resolve(domain, "txt")
                for data in spf:
                    if re.search(r"include:spf.protection.outlook.com", str(data)):
                        return "correct"
                        ans = 1
                        break
                    else:
                        pass
                if ans != 1:
                    return "misconfigured"
            except Exception:
                return "misconfigured"
        if type == "sipdir":
            try:
                tls = dns.resolver.resolve("_sip._tls."+domain, "SRV")
                if tls:
                    return "correct"
            except Exception:
                return "misconfigured"
        if type == "sipfed":
            try:
                tcp = dns.resolver.resolve("_sipfederationtls._tcp."+domain, "SRV")
                if tcp:
                    return "correct"
            except Exception:
                return "misconfigured"

    def mail_search():
        domain_exchange = []
        exchange_list = []
        ans = 0
        with open("mail_list.txt", "r", encoding="utf-8") as read:
            for line in read:
                split = line.split(" ")
                domain_exchange.extend([split[0]])
                exchange_list.extend([split[1]])
        try:
            m = dns.resolver.resolve(domain, "MX")
            mx_list = []
            pref_list = []
            for rdata in m:
                mx = [rdata.exchange]
                pref = [rdata.preference]
                mx_list.extend(mx)
                pref_list.extend(pref)
            mx_name = str(mx_list[(pref_list.index(min(pref_list)))])
        except dns.resolver.NoAnswer:
            return "misconfigured"
        with open("mail_list.txt", "r", encoding="utf-8") as file_path:
            for count, line in enumerate(file_path):
                pass
        count += 1
        num = 0
        while num < count:
            if domain_exchange[num] in mx_name:
                ans = 1
                return exchange_list[num]
                break
            else:
                num += 1
        if ans == 0:
            return "misconfigured"

    def www_check():
        try:
            a = dns.resolver.resolve("www."+domain, "A")
            if a:
                return "correct"
        except Exception:
            return "none"

    context = {
        "domain": domain,
        "a": record_search("a"),
        "aaaa": record_search("aaaa"),
        "ns": record_search("ns"),
        "mx": record_search("mx"),
        "txt": record_search("txt"),
        "soa": record_search("soa"),
        "whois_ns": whois_ns_compare(),
        "ns_ip": ns_ip_compare(),
        "asn": as_search("asn"),
        "country": as_search("country"),
        "registry": as_search("registry"),
        "description": as_search("description"),
        "registrar": regi_search(),
        "exp_date": exp_date(),
        "auto": o365check("auto"),
        "msoid": o365check("msoid"),
        "lync": o365check("lync"),
        "365mx": o365check("365mx"),
        "spf": o365check("spf"),
        "sipdir": o365check("sipdir"),
        "sipfed": o365check("sipfed"),
        "mail_search": mail_search(),
        "www": www_check(),


    }
    return HttpResponse(template.render(context, request))

