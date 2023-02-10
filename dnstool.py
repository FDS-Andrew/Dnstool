from check_validity import Check
from search_engine import Resolver, Whois
domain_name = input("Enter domain name: ")

check = Check(domain_name)

if check.validity():
    resolver = Resolver(domain_name)
    whois = Whois(domain_name)
    
    print(resolver.get_mx_record())
    print(whois.get_registrar())
        
else:
    print("Input domain invalid")
