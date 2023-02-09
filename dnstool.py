from check_validity import Check
from resolver_record import Resolver
from whois_record import Whois_Records

domain_name = input("Enter domain name: ")

check = Check(domain_name)

if check.validity():
    whois_records = Whois_Records(domain_name)
    resolver = Resolver(domain_name)

else:
    print("Input domain invalid")
