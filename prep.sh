sudo apt-get update
sudo apt upgrade
sudo apt install dnsrecon
sudo apt install whois
sudo apt install python3-pip
pip install python-whois --upgrade
pip install dnspython --upgrade
echo "alias digdns='bash digdns.sh'" >> ~/.bash_aliases
source ~/.bash_aliases
