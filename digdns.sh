#setup
bash setup
echo -e "enter domain name"
read var
echo $var > domain.txt
dnsrecon -d $var -t std --lifetime 10 > stdtemp.txt

#DNS records
echo -e '\nA records \n'
dig $var -t a
echo -e '\nAAAA records \n'
dig $var -t aaaa
echo -e '\nCAA records \n'
dig $var -t caa
echo -e '\nMX records \n'
cat stdtemp.txt | grep -w " MX" | cut -f 2
echo -e '\nNS records \n'
cat stdtemp.txt | grep -w " NS" | cut -f 2
echo -e '\nSRV records \n'
cat stdtemp.txt | grep -w " SRV" | cut -f 2
echo -e '\nTXT records \n'
cat stdtemp.txt | grep -w " TXT" | cut -f 2
echo -e '\nSOA records \n'
dig $var -t soa
echo -e '\nDS records \n'
host -t ds $var
echo -e '\nDNSKEYs \n'
cat stdtemp.txt | grep "NSEC " | cut -f 2
cat stdtemp.txt | grep "NSEC3 " | cut -f 2

#ASN
echo -e '\nAS number \n'

#domain server

echo -e 'Domain server:'
host -t a $var | grep 'has address' | cut -d ' ' -f 4 > domainip.txt
if [[ $(cat domainip.txt | wc -l) -gt 0 ]] ; then
whois -h whois.cymru.com $(cat domainip.txt) -H
fi

#nameserver

echo -e 'Nameserver:'
cat stdtemp.txt | grep -w " NS" | sort -d | grep . | grep -v -F : | wc -l > nscount.txt
nscount=1
while [[ nscount -le $(cat nscount.txt) ]] ; do
cat stdtemp.txt | grep -w " NS" | sort -d | grep -v -F : | sed -n $(echo $nscount)p | cut -d " " -f 5 > nsip.txt
whois -h whois.cymru.com $(cat nsip.txt) -H
nscount=$(($nscount + 1 )) ;
done

#Registrar
echo -e '\nRegistrar Info \n'
whois $var > regex.txt
cat regex.txt | sed s/'   R'/'R'/ | grep -w -E --no-ignore-case 'Registration Service'\|'Registrar:' | grep . | sort -u -f

#NS
echo -e '\nNS comparison'

#ns printing

echo -e '\nDnsrecon:'
cat stdtemp.txt | grep -w " NS" | sort -d | cut -f 2 | sed s/NS/' '/ | cut -d ' ' -f 4 | sort -u > reconns.txt
cat reconns.txt        #dnsrecon result
echo -e '\nWhois:'
whois $var -H | grep -i 'Domain servers' -A 4 | grep -i 'Domain servers' -v | cut -d ' ' -f 7 > dsns.txt
whois $var -H | grep -i 'Name Server' | cut -d ' ' -f 6 > nsns.txt
if [[ $(cat dsns.txt | wc -l) -gt 0 ]] ; then
  cat dsns.txt        #whois result when format is domain servers
  whois=1
elif [[ $(cat nsns.txt | wc -l) -gt 0 ]] ; then
  cat nsns.txt        #whois result when format is name servers
  whois=2
else
  echo -e '\n  **No Whois record**\n'
  whois=0
fi

#ns comparing

if [[ $(echo $whois) -eq 0 ]] ; then
  echo -e '  **No Whois record to compare**'
elif [[ $(echo $whois) -eq 1 ]] ; then
  cat dsns.txt reconns.txt | sort -u -f | grep . | wc -l > nscomp.txt      #if names are same sort -u
  if [[ $(cat dsns.txt | grep . | wc -l) -eq $(cat nscomp.txt) ]] ; then
    echo -e '\n  NS configuration correct\n'     #when the num of sorted names are same with dsns num
  else
    echo -e '\n  **Warning different server names**\n'
  fi

elif [[ $(echo $whois) -eq 2 ]] ; then
  cat nsns.txt reconns.txt | sort -u -f | grep . | wc -l > nscomp.txt
  if [[ $(cat nsns.txt | grep . | wc -l) -eq $(cat nscomp.txt) ]] ; then    #same as dsns but nsns
    echo -e '\n  Ns configuration correct\n'
  else
    echo -e '\n  **Warning different server names**\n'
  fi
fi
#ip comparing
echo -e '\nComparing IP\n'
cat stdtemp.txt | grep -w " NS" | sort -d | cut -f 2 | sed s/NS/' '/ | cut -d ' ' -f 5 | grep -v -F : > nsip.txt
cat nsip.txt
cat nsip.txt | wc -l > nsipcount.txt
cat nsip.txt | cut -d '.' -f 1,2,3 | sort -u | wc -l > nsipcomp.txt  #if mask 24 same sort -u
if [[ $(cat nsipcount.txt) -eq $(cat nsipcomp.txt) ]] ; then   #if num changes it means duplicates
  echo -e '\n  Ip configuration correct'
else
  echo -e '\n  **Warning DNS nested in same IP**'
fi

#email service
echo -e '\nEmail service \n'
cat stdtemp.txt | grep 'MX' | cut -d ' ' -f 4 > mail.txt     #using same format to search email

bash mailsearch          #run separate code

#cleaning
cat setup | grep touch | sed s/touch/rm/ > clean
bash clean

