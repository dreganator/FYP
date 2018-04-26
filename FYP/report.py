import subprocess
from subprocess import call
import time
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import sys
import os
from textwrap import wrap
import re

 
canvas = canvas.Canvas("Report1.pdf", pagesize=letter)
t = canvas.beginText()
canvas.setLineWidth(.3)
canvas.setFont('Helvetica', 12)



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
canvas.drawString(30,750, 'Commenced at '+time.strftime("%d:%m:%y"))
canvas.drawString(30,735,'These are the addresses discovered on your network')
depth=720
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

	result += ' '.join(cve)
	print "\n These are the CVE's detected on host "+ discov[i]+ "\n"
	print result
	

#	for i in range (len(discov)):
#		depth=depth-15
#		canvas.drawString(30,depth, discov[i])


	depth = depth-60
	canvas.drawString(30, depth,'This is the nmap scan result from '+discov[0])
	depth = depth -30
	t.setTextOrigin(30, depth)
	wraped_text = "\n".join(wrap(result, 80)) #80 is line width in page
	t.textLines(wraped_text)
	canvas.drawText(t)


#if statement needed for when no cves are recovered
#############################


#print cve
#print cves




#print "we found these cves "+cves[0]


############################################################################



#for i in range (len(cves)):
#	depth=depth-15
#	canvas.drawString(30,depth, cves[i])


#for i in range (len(scanz)):

#	depth = depth-15
#	#width = width+10
#	canvas.drawString(30, depth, scan)
 
canvas.save()
