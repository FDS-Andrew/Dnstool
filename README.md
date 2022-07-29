# Dnstool [![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/FDS-Andrew/Dnstool.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/FDS-Andrew/Dnstool/context:python)
## 功能
1. 查A、AAAA、MX、NS、SRV、TXT、SOA、PTR、WWW records
2. 查ASN和國家
3. 查EmailProvider、Registrar 和網域到期日
4. 比較Whois的NS是否設錯
5. 比較DNS是否放在同個IP
6. 嘗試對DNS進行zone transfer(A, CNAME, MX, TXT, SRV)
7. 驗證是否有Office 365必要records
## 安裝
1. `git clone https://github.com/FDS-Andrew/Dnstool.git`
2. `cd Dnstool`
3. `bash prep.sh` 
4. 若想使用digdns或newrecon輸入`source ~/.bash_aliases` 
## 使用
1. 在terminal輸入`python3`若使用python console則不需
2. `>>>import dnsquery`
3. `>>>dnsquery.query("domain_name.com", "type")`
## type
1. **std:** 包含A、AAAA、MX、NS、TXT、SOA、ASN、Registrar、Expiration date、Email service provider、Whois NS evaluation和DNS IP evaluation
2. **srv:** SRV record
3. **mail:** Email service provider
4. **asn:** ASN
5. **reg:** Registrar(註冊商)
6. **exp:** Expiration date(網域到期日)
7. **eva:** Whois NS evaluation和DNS IP evaluation
8. **ptr:** reverse lookup
9. **xfr:** Zone transfer嘗試將DNS裡的record提出
10. **365:** 驗證是否有各項Office 365 records
## 備註
> 1. 若要用digdns不要改 **`~/.digrc`** *(若要自用 **dig** 請加 `-r` )*
> 2. 若不使用python可用`digdns`或`newrecon` 
> 4. 若要追加 **common srv service** 可改 **srvlist.txt**
> 5. 若追加 **email service provider** 可改 **mail_list.txt**
