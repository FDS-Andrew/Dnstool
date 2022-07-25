# Dnstool [![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/FDS-Andrew/Dnstool.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/FDS-Andrew/Dnstool/context:python)
## 功能
1. 查A、AAAA、MX、NS、SRV、TXT、SOA、PTR records
2. 查ASN和國家
3. 查EmailProvider、Registrar 和網域到期日
4. 比較Whois的NS是否設錯
5. 比較DNS是否放在同個IP
6. 嘗試對DNS進行zone transfer
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
2. **all:** 比std多SRV record
3. **srv:** SRV record
4. **mail:** Email service provider
5. **asn:** ASN
6. **reg:** Registrar(註冊商)
7. **exp:** Expiration date(網域到期日)
8. **eva:** Whois NS evaluation和DNS IP evaluation
9. **ptr:** reverse lookup
10. **xfr:** Zone transfer嘗試將DNS裡的record提出
## 備註
> 1. 若要用digdns不要改 **`~/.digrc`** *(若要自用 **dig** 請加 `-r` )*
> 2. 若不使用python可用`digdns`或`newrecon` 
> 4. 若要追加 **common srv service** 可改 **srvlist.txt**
> 5. 若追加 **email service provider** 可改 **mail_list.txt**
