sudo apt-get update
sudo apt upgrade
sudo apt install dnsrecon
sudo apt install whois
sudo apt install python3-pip
pip install python-whois --upgrade
pip install dnspython --upgrade
pip install ipwhois --upgrade
touch ~/.bash_aliases
echo "alias digdns='bash digdns.sh'" >> ~/.bash_aliases
echo "alias newrecon='bash newrecon.sh'" >> ~/.bash_aliases
