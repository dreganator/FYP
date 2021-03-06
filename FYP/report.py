import subprocess
from subprocess import call
import time
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import BaseDocTemplate, Frame, PageTemplate
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.enums import TA_CENTER
import sys
import os
from textwrap import wrap
from BeautifulSoup import BeautifulSoup
import urllib2 
import requests
import re

 
canvas = canvas.Canvas("Report1.pdf", pagesize=letter)
t = canvas.beginText()
canvas.setLineWidth(.3)
canvas.setFont('Helvetica', 12)
styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name='centered', alignment=TA_CENTER))
c = canvas
canvas.setTitle("Scan output")

def hello(c):
    from reportlab.lib.units import inch

    #First Example
    c.setFillColorRGB(1,0,0) #choose your font colour
    c.setFont("Helvetica", 30) #choose your font type and font size
    c.drawString(30,760,"BoxSec") # write your text
    
hello(c)

canvas.setLineWidth(.3)
canvas.setFont('Helvetica', 12)
c.setFillColorRGB(0,0,0)

###############################################
import subprocess, sys
## command to run - tcp only ##
cmd = "./discovery.sh"
 
## run it ##
p = subprocess.Popen(cmd, shell=True,
stdout=subprocess.PIPE,
stderr=subprocess.PIPE,
stdin=subprocess.PIPE)

out, err = p.communicate()
discover = out
discov = discover.split()
#################################################################
#contains the output of all cves and scan
scanz = []

#contains all cves
cves =[]
################################

canvas.drawString(30,720, 'Scan Commenced on the '+time.strftime("%d/%m/%y at %H:%M"))

depth=690
width=30

###############################


i = 0
for i in range (len(discov)):
	#contains cves for this particular scan
	cve = []
	
	#captures for this particular scan
	scan = ""
	result = ""
	cmd = "nmap --script nmap-vulners,vulscan --script-args vulscandb=cve.csv -sV "+discov[i]
	p = subprocess.Popen(cmd, shell=True,
	stdout=subprocess.PIPE,
	stderr=subprocess.PIPE,
	stdin=subprocess.PIPE)
	out, err = p.communicate()
	########################## End of scanning process
		
	scan = scan + out+ " "+"This is the scan result from "+discov[i]
	#adds all cves to the global cves list
	cves = re.findall('\[.*?\]', scan)
	#adds cves from this particular scan to list
	cve = re.findall('\[.*?\]', scan)
	####################################################
	#get rid of brackets
	cves = [s.replace('[', '') for s in cves]
	cves = [s.replace(']', '') for s in cves]
	cve = [s.replace('[', '') for s in cves]
	cve = [s.replace(']', '') for s in cves]

####################################################################

	prefix = 'CVE'
	for word in cve[:]:
		if not word.startswith(prefix):
			cve.remove(word)
	for word in cves[:]:
		if not word.startswith(prefix):
			cves.remove(word)
#Incase bracket contents aren't CVE's


		

###############################################################################################

	result += ', '.join(cve)
	print "\n These are the CVE's detected on host "+ discov[i]+ "\n"
	print result
	


	depth = depth-25
	canvas.drawString(30, depth,'This is the nmap scan result from '+discov[i])
	depth = depth-15	
	t.setTextOrigin(30, depth)
	wraped_text = "\n".join(wrap(result, 80)) #80 is line width in page
	depth = depth -50

	if result == '':
		depth = depth +40
		canvas.drawString(30, depth, "(No CVE's were detected on "+discov[i]+")")
	t.textLines(wraped_text)
	canvas.drawText(t)


###############################################################################################


 
canvas.save()
