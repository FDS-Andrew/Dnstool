# A different approach to recon

# setup
num=0
RED='\033[0;31m'     # colorcode
NA='\033[0m'
LGREEN='\033[1;32m'
reconvar=( A AAAA MX NS TXT DS )  # trivial records
touch ~/.digrc  # dig format
echo +nocmd +nocomments +nostats +noquestion +noauthority +noadditional +multiline > ~/.digrc

# trivial search
echo -e "${LGREEN}Please enter domain name${NA}"
read var
while [[ $num -le 5 ]] ; do 
  echo -e "\n${LGREEN}${reconvar[$num]} records:${NA}\n"
  if [[ $(dig $var -t $(echo ${reconvar[$num]}) | wc -l) -eq 0 ]] ; then
    echo -e "${RED}No ${reconvar[$num]} records${NA}"
  else
    dig $var -t $(echo ${reconvar[$num]}) | grep "${reconvar[$num]}"
  fi
  num=$(($num + 1 ))
done

# SOA search
echo -e "\n${LGREEN}SOA records:${NA}\n"
if [[ $(dig $var -t soa | wc -l) -eq 0 ]] ; then
  echo -e "${RED}No SOA records${NA}"
else
  dig $var -t soa 
fi

#SRV record
echo -e "\n${LGREEN}SRV records:${NA}\n"
srvlist=$(cat srvlist.txt | wc -l)
num=1
while [[ num -le srvlist ]] ; do
  dig -t srv $(echo $(cat srvlist.txt | sed -n $(echo $num)p)$var) | grep SRV
  num=$(($num+1))
done

# AS & Country query
nscount=$(dig -t ns $var | grep 'NS' | wc -l)           # NS count
echo -e "\n${LGREEN}AS number of         ${NA}$var\n"    # domain AS
if [[ $(dig -t a $var | cut -d 'A' -f 2 | wc -l) -gt 0 ]] ; then
  whois -h whois.cymru.com $(dig -t a $var | cut -d 'A' -f 2) 
elif [[ $(dig -t aaaa $var | cut -d 'I' -f 2 | cut -d ' ' -f 3 | wc -l) -gt 0 ]] ; then
  whois -h whois.cymru.com $(dig -t aaaa $var | cut -d 'I' -f 2 | cut -d ' ' -f 3)
else  
  echo -e "$var ${RED}has no AS number${NA}\n"
fi

# NS AS
num=1
while [[ $num -le $nscount ]] ; do
  ns[$num]=$(dig -t ns $var | grep 'NS' | cut -d 'S' -f 2 | sort -u | sed -n $(echo $num)p)
  nsip[$num]=$(dig -t a $(echo -e ${ns[$num]}) | cut -d 'A' -f 2)
  echo -e "\n${LGREEN}AS number of ${NA}$(echo -e ${ns[$num]})"
  whois -h whois.cymru.com $(echo ${nsip[$num]})
  nsip[$num]=$(echo -e ${nsip[$num]} | cut -d '.' -f 1-3)  # prep for ip comparison
  num=$(($num + 1 ))
done      

# NS name compare
whoisns=$(whois $var -H | grep -i 'Domain servers' -A 4 | grep -i 'Domain servers' -v | cut -d ' ' -f 7 | sort -u)
if [[ $(echo -e $whoisns | grep . | wc -l) -eq 0 ]] ; then   # whois ns
  whoisns=$(whois $var -H | grep -i 'Name Server' | cut -d ' ' -f 6 | sort -u)
  if [[ $(echo -e $whoisns | wc -l ) -eq 0 ]] ; then
    echo -e "\n${RED}No Whois record \n ${NA}"
  fi
fi
digns=$(dig -t ns $var | grep 'NS' | cut -d 'S' -f 2 | sort -u | sed s/'. '/' '/g | sed 's/.$//')  # dig ns
whoisns=${whoisns,,}   # some whois profile is upper-case
digns=${digns,,}
if [[ $(echo $whoisns) = $(echo $digns) ]] ; then
  echo -e "\n${LGREEN}NS record configuration correct \n ${NA}"
else
  echo -e "\n${RED}NS record configuration incorrect \n ${NA}"
fi
 
# NS ip compare
num=1
while [[ $num -le $nscount ]] ; do
  num2=$(($num+1))
  if [[ $(echo -e ${nsip[$num]}) = $(echo -e ${nsip[$num2]}) ]] ; then
    echo -e "\n${RED}NS nested in same IP\n${NA}"
    num=$nscount 
  fi
  num=$(($num+1))
done
  
# Registrar
echo -e "\n${LGREEN}Registrar Info \n${NA}"
whois $var | sed s/'   R'/'R'/ | grep -w -E --no-ignore-case 'Registration Service'\|'Registrar:' | grep . | sort -u -f | head -n 1

#Mail service
echo -e "\n${LGREEN}Mail service \n${NA}"
python3 mailsearchv2.py
