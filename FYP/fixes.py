from BeautifulSoup import BeautifulSoup
import urllib2
import re 
import requests

cve = 'CVE-2016-2278'

html_page = urllib2.urlopen('https://nvd.nist.gov/vuln/detail/'+cve)
soup = BeautifulSoup(html_page)
linklist = ""
data = soup.findAll('div', attrs={'class':'row col-sm-12'})
#print data
for div in data:
    links = div.findAll('a')

    for a in links:
	try:

		aString = a['href']
		
		
		if aString.startswith("http")==True:
			linklist+= aString+"\n"	


	except KeyError:
		pass
print linklist






#print(links)
#print(table)
