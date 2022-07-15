# Dnstool教學 [![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/FDS-Andrew/Dnstool.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/FDS-Andrew/Dnstool/context:python)
## 功能
1. 查A、AAAA、MX、NS、SRV、TXT、SOA、DS *(大部分 domain 都沒有)* records
2. 查ASN和國家
3. 查EmailProvider和ISP *(Registrar)*
4. 比較Whois的NS名字有沒有設錯 *(若 NS 中有 record 設錯會有 ***warning***)* 
5. 比較NS的IP有沒有放在同一個地方
## 安裝
1. `git clone https://github.com/FDS-Andrew/Dnstool.git`
2. `cd Dnstool`
3. `bash prep.sh` *幫你裝dnsrecon，whois和python3*
4. `source ~/.bash_aliases` *幫你建alias*
## 使用
1. `digdns` *利用dnsrecon的database，功能完整，mailsearch已沒再更新*
2. `newrecon` *沒用到dnsrecon，速度較快，不提供email資訊，srvlist.txt可再添加資料*
3. `dnsquery` *一樣的功能不過是用python寫的*
## 備註
> 1. :exclamation::exclamation: 不要改 **`~/.digrc`** 不然會炸開 *(若要自用 **dig** 請加 `-r` )*
> 2. Email provider是另外跑`bash mailsearch.sh`扒出來的
> 3. 如果查的domain的MXrecord是自設的會跑比較久 *(因為 `mailsearch.sh` 會重複跑whois)*
> 4. AS是用 `whois.cymru.com` 扒出來的
> 5. **`newrecon.sh`** 這個shell是重寫的，目的是減少電腦負擔及加速過程，且大幅減少txt檔的使用率
> 6. 如果不需要**email provider**資訊的話可以跑 `newrecon` 跑得快很多 *(因為沒用到 **dnsrecon**)*
> 7. 如果跑不出資料請先 `ping <domain_name> -c <看你要ping幾次>` 來確定連不連的到domain 
> 8. 如果要追加 **common srv service** 可以改 **srvlist.txt** 且不用改 `newrecon.sh`
