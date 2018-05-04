from bs4 import BeautifulSoup
import requests

cve = 'CVE-2012-1006'

def scraping(cve):
	parsers = ['html.parser']
	r=requests.get('https://nvd.nist.gov/vuln/detail/'+cve)
	soup=BeautifulSoup(r.content, "lxml")
	i=0


	size = len(soup.find_all('p'))

	description = soup.find_all('p')[25].text

	crit = soup.find_all('p')[27].text
	i=0	
	more = []
	for line in crit.splitlines():
	
		if i ==4:
			critical = line
		i=i+1
	
	print cve
	print "Description: "+description
	print "Severity Rating: "+critical

scraping(cve)

