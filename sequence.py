import math
import numpy as np
import pandas as pd
import statistics as stat
import sys

tb = pd.read_csv('lbnl.anon-ftp.03-01-14.csv')

tcp = tb[tb['Protocol']=='TCP']
tcpsyn = tcp[tcp['Info'].str.find('[SYN]')>-1] 
tcpsyn1 = tcpsyn

tcpsyn = tcpsyn.sort_values('Source', ascending=False)
tcpsyn = tcpsyn.drop_duplicates(subset ='Source', keep = 'first') 

tcpsyn1 = tcpsyn1.sort_values('Destination', ascending=False)
tcpsyn1 = tcpsyn1.drop_duplicates(subset ='Destination', keep = 'first')

sources = tcpsyn['Source'].to_list() 
destinations = tcpsyn1['Destination'].to_list()

tb = tb[tb['Protocol']=='TCP']
splist = tb['Info'].to_list()
splistnw = [i.split(' ')[0] for i in splist]
tb = tb.assign(Souport = splistnw)
splistnw = [(i.split(' ')[4]) for i in splist]
tb = tb.assign(Desport = splistnw)

timeseq,timeak,sequences,acks = [],[],[],[]

sourc = str(sys.argv[1])
destinatn = str(sys.argv[2])
sourcepo = str(sys.argv[3])
desnpo = str(sys.argv[4])

server,client,serverpo,clientpo = '','','',''

if(sourc in sources):
	client = sourc
	clientpo = sourcepo
	server = destinatn
	serverpo = desnpo
else:
	client = destinatn
	clientpo = desnpo
	server = sourc
	serverpo = sourcepo

tbconnsq = tb[(tb.Source==server) & (tb.Destination==client) & (tb.Souport==serverpo) & (tb.Desport==clientpo)] 
tbconnak = tb[(tb.Source==client) & (tb.Destination==server) & (tb.Souport==clientpo) & (tb.Desport==serverpo)]
tbconnsq = tbconnsq.reset_index()
tbconnak = tbconnak.reset_index()

timefins = []

for i in tbconnsq.index:
	info = tbconnsq['Info'][i]
	if(info.find('[SYN, ACK]')>-1 or info.find('[FIN, ACK]')>-1):
		if(info.find('[FIN, ACK]')>-1):
			timefins.append(('f',tbconnsq.loc[i, "Time"]))
		sequences.append((info.split(' ')[7]).split('=')[1])
		timeseq.append(tbconnsq.loc[i, "Time"])
	if(info.find('[SYN]')>-1 or info.find('[ACK]')>-1 or info.find('[RST]')>-1):
		if(info.find('[RST]')>-1):
			timefins.append(('f',tbconnsq.loc[i, "Time"]))
		sequences.append((info.split(' ')[6]).split('=')[1])
		timeseq.append(tbconnsq.loc[i, "Time"])
	if(info.find('[SYN, ECN, CWR]')>-1):
		timefins.append(('s',tbconnsq.loc[i, "Time"]))
		sequences.append((info.split(' ')[8]).split('=')[1])
		timeseq.append(tbconnsq.loc[i, "Time"])

for i in tbconnak.index:
	info = tbconnak['Info'][i]
	if(info.find('[SYN, ACK]')>-1 or info.find('[FIN, ACK]')>-1):
		if(info.find('[FIN, ACK]')>-1):
			timefins.append(('f',tbconnsq.loc[i, "Time"]))
		acks.append((info.split(' ')[8]).split('=')[1])
		timeak.append(tbconnak.loc[i, "Time"])
	if(info.find('[ACK]')>-1):
		acks.append((info.split(' ')[7]).split('=')[1])
		timeak.append(tbconnak.loc[i, "Time"])

myList = []
for i in range(len(timeseq)):
	myList.append((timeseq[i],"seq",sequences[i]))
for i in range(len(timeak)):
	myList.append((timeak[i],"ack",acks[i]))
myList.sort(key = lambda x: x[0])

flows = []

i=0
while i<len(timefins)
	tmend = timefins[i][1]
	typo = timefins[i][0]
	for i in range(len(myList)):
		if(myList[i][0] <= tmend):
			ans.append(myList[i])
else:
	ans = myList

print(ans)
