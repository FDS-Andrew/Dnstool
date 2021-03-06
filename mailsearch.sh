#check if dnsrecon had mx record
if [[ $(cat mail.txt | wc -l ) -eq 0 ]] ; then   #if not then try host -t mx
  host -t mx $(cat domain.txt) | grep 'has address' | cut -d ' ' -f 1 > mail.txt
  if [[ $(cat mail.txt | wc -l ) -gt 0 ]] ; then       #if there is mx record then run script again
    bash mailsearch.sh
  fi
  if [[ $(cat mail.txt | wc -l ) -eq 0 ]] ; then     #if still no record exit script
    echo -e '  **No email record**'
  fi

#comparing mx record to known email providers

elif [[ $(cat mail.txt | grep -i 'aspmx.l.google.com' -c) -gt 0 ]] ; then
  echo -e 'Google Workspace'
elif [[ $(cat mail.txt | grep -i 'smtp.google.com' -c) -gt 0 ]] ; then
  echo -e 'Gmail'
elif [[ $(cat mail.txt | grep -i 'gmail-smtp-in.l.google.com' -c) -gt 0 ]] ; then
  echo -e 'Gmail'
elif [[ $(cat mail.txt | grep -i 'outlook.com' -c) -gt 0 ]] ; then
  if [[ $(cat mail.txt | grep -i 'mail.protection.outlook.com' -c) -gt 0 ]] ; then
    echo -e 'Microsoft Exchange Online'
  else               #if format is wrong display warning
    echo -e '  **Warning please update MX record version --Microsoft Exchange'
  fi
elif [[ $(cat mail.txt | grep -i 'hinet.net' -c) -gt 0 ]] ; then
  echo -e 'HiNet Mail'
elif [[ $(cat mail.txt | grep -i 'amazon.com' -c) -gt 0 ]] ; then
  echo -e 'Amazon SES'
elif [[ $(cat mail.txt | grep -i 'yahoodns.net' -c) -gt 0 ]] ; then
  echo -e 'Yahoo! Mail'
elif [[ $(cat mail.txt | grep -i 'mailcloud.com.tw' -c) -gt 0 ]] ; then
  echo -e 'Mailcloud'
elif [[ $(cat mail.txt | grep -i 'mimecast.com' -c) -gt 0 ]] ; then
  echo -e 'Mimecast'
elif [[ $(cat mail.txt | grep -i 'messagelabs.com' -c) -gt 0 ]] ; then
  echo -e 'MessageLabs'
elif [[ $(cat mail.txt | grep -i 'pphosted.com' -c) -gt 0 ]] ; then
  echo -e 'ProofPoint'
else

#if none match 

host -t mx  $(cat mail.txt | sort -R | head -n 1) | grep 'has address' | cut -d ' ' -f 4 | grep -v -F : | sort -R | head -n 1 > unknown.txt       #check for mx record ip and perform whois
if [[ $(cat unknown.txt | wc -l) -eq 0 ]] ; then
host -t a $(cat mail.txt | sort -R | head -n 1) | grep 'has address' | cut -d ' ' -f 4 | grep -v -F : | sort -R | head -n 1 > unknown.txt         #if multiple ip use sort -R(random) for whois
fi
  if [[ $(cat unknown.txt | wc -l) -eq 0 ]] ; then     #if no mx record ip stop script
      echo -e '  **No email record in database**'
  else

#using whois result and turn it to mail.txt format

    whois $(cat unknown.txt) > whois.txt
    cat whois.txt | grep -w -E -i 'e-mail'| tail -n 1 | cut -d '@' -f 2 | cut -d ' ' -f 1 > mail.txt
    if [[ $(cat mail.txt | wc -l) -eq 0 ]] ; then
    cat whois.txt | grep -A 1 'Administrative contact\|Administrator contact'| tail -n 1 | cut -d '@' -f 2 | cut -d ' ' -f 1 > mail.txt
    fi
    if [[ $(cat mail.txt | wc -l) -eq 0 ]] ; then
    cat whois.txt | grep --no-ignore-case 'Email:' | tail -n 1 | cut -d '@' -f 2 > mail.txt
    fi
    if [[ $(cat mail.txt | wc -l) -eq 0 ]] ; then    #if no whois result stop script
    echo -e '  **No email record**'
    elif [[ $(cat mail.txt) == $(cat xmail.txt) ]] ; then  #if mail.txt is the same for second round stop script
    echo -e '  **No email record in database**'
    else
    cat mail.txt > xmail.txt
    bash mailsearch.sh      #if there is result run script again
    fi
  fi
fi
