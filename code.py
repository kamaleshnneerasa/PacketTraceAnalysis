import math
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import sys

def readCSVfile(inputFile):
    tb = pd.read_csv(inputFile)

    tcp = tb[tb['Protocol']=='TCP']
    tcpsyn = tcp[tcp['Info'].str.find('SYN')>-1] 
    tcpsyn = tcpsyn[tcpsyn['Info'].str.find('[SYN, ACK]')==-1]

    tcpsyn1 = tcpsyn

    tcpsyn = tcpsyn.sort_values('Source', ascending=False)
    tcpsyn = tcpsyn.drop_duplicates(subset ='Source', keep = 'first') 

    tcpsyn1 = tcpsyn1.sort_values('Destination', ascending=False)
    tcpsyn1 = tcpsyn1.drop_duplicates(subset ='Destination', keep = 'first')

    sources = tcpsyn['Source'].to_list() 
    destinations = tcpsyn1['Destination'].to_list()

    print "# of unique Server IPs: ",len(sources)
    print "# of unique Client IPs: ",len(destinations)

    findTCPflows((sources,destinations,tb))

def findTCPflows(lists):
    sources = lists[0]
    destinations = lists[1]
    tb = lists[2]
    tcpFlows,counter = [[]],0
    for srcIP in sources:
        tb_dash = tb[(tb.Source==srcIP) | (tb.Destination==srcIP)]
        for ind in tb_dash.index:
            time,src,dst = tb['Time'][ind],tb['Source'][ind],tb['Destination'][ind]
            protocol,length,info = tb['Protocol'][ind],tb['Length'][ind],tb['Info'][ind]
            if(srcIP==src):
                if(protocol=='TCP' and (info.find('[SYN]')>-1 or info.find('[SYN, ECN, CWR]')>-1)):
                    temp = info.split(" ")
                    port,flag = temp[0],True
                    record = {'SrcPort':port,'DestIP':dst,'Start':time,'End':-1, 'BytesSent':length, 'BytesReceived':0}
                    for i in range(len(tcpFlows[counter])):
                        rec = tcpFlows[counter][i]
                        if(rec['SrcPort']==port and rec['End']!=-1):
                            tcpFlows[counter][i] = record
                            flag = False
                    if(flag==True):
                        tcpFlows[counter].append(record)
                if(protocol=='TCP' and (info.find('[FIN, ACK]')>-1 or info.find('[RST]')>-1)):
                    #if(info.find('[RST]')>-1):
                        #print("Hey")
                    temp = info.split(" ")
                    port = temp[0]
                    for i in range(len(tcpFlows[counter])):
                        rec = tcpFlows[counter][i]
                        if(rec['SrcPort']==port and rec['End']==-1):   #Please check the end part
                            rec['End'] = time
                            rec['BytesSent'] = rec['BytesSent']+length
                            tcpFlows[counter][i] = rec
                if(protocol=='TCP' and info.find('[ACK]')>-1):
                    for i in range(len(tcpFlows[counter])):
                        rec = tcpFlows[counter][i]
                        if(rec['SrcPort']==port and rec['End']==-1): #Please check me
                            rec['BytesSent'] = rec['BytesSent']+length
                            tcpFlows[counter][i] = rec
            elif(srcIP==dst):           #Packets sent from server to the client
                if(protocol=='TCP' and info.find('[ACK]')>-1):
                    temp = info.split(" ")
                    port = temp[4]
                    for i in range(len(tcpFlows[counter])):
                        rec = tcpFlows[counter][i]
                        if(rec['SrcPort']==port and rec['End']==-1):
                            rec['BytesReceived'] = rec['BytesReceived']+length
                            tcpFlows[counter][i] = rec
                if(protocol=='TCP' and (info.find('[FIN, ACK]')>-1 or info.find('[RST]')>-1)):
                    temp = info.split(" ")
                    port = temp[4]
                    for i in range(len(tcpFlows[counter])):
                        rec = tcpFlows[counter][i]
                        if(rec['SrcPort']==port and rec['End']==-1): #Please check the end part
                            rec['End'] = time
                            rec['BytesReceived'] = rec['BytesReceived']+length
                            tcpFlows[counter][i] = rec
        tcpFlows.append([])
        counter = counter+1
        #print(counter)
    numFlows(tcpFlows)
    connectionDuration(tcpFlows)
    dataTransferred(tcpFlows)
    traffic(tcpFlows)

def numFlows(tcpFlows):
    numFlows = 0
    for flowList in tcpFlows:
        numFlows = numFlows + len(flowList)
    print "# of unique TCP Fows: ", numFlows

def traffic(tcpFlows):
    activeFlows = []
    for i in range(24):
        activeFlows.append(0)
    for flowList in tcpFlows:
        for flow in flowList:
            start,end = int(flow['Start']/3600),int(flow['End']/3600)
            for i in range(start,end+1):
                activeFlows[i] = activeFlows[i]+1
    index = np.arange(24)
    plt.bar(index,activeFlows)
    plt.title('Traffic in one each hour')
    plt.savefig(sys.argv[1]+'traffic.png')
    #plt.show()

def connectionDuration(tcpFlows):
    flowtime = []
    for flowList in tcpFlows:
        for flow in flowList:
            if(flow['End']!=-1):
                duration = (flow['End']-flow['Start'])/60       # duration is in seconds
                flowtime.append(duration)
    flowtime.sort()
    print(flowtime)
    probability = []
    flowtime = [x*60 for x in flowtime]
    totalFlows = len(flowtime)
    end = flowtime[totalFlows-1]
    for i in range(totalFlows):
        probability.append(((i+1)*1.0)/totalFlows)
    plt.plot(flowtime,probability)
    plt.title('# of Connections vs Connection Time')
   # plt.axis([-500,end,-0.1,2.0])
    plt.show()
    plt.savefig(sys.argv[1]+'connectionTime.png')
    #plt.show()
    print "# of ValidFlows: ",totalFlows

def dataTransferred(tcpFlows):
    flowDuration = []
    bytesSent = []
    bytesReceived = []
    for flowList in tcpFlows:
        for flow in flowList:
            if(flow['End']!=-1):
                duration = (flow['End']-flow['Start'])
                bytesSent.append(flow['BytesSent'])
                bytesReceived.append(flow['BytesReceived'])
                flowDuration.append(duration)
    plt.plot(flowDuration,bytesSent,'ro')
    plt.title('BytesSent vs Connection Time')
    plt.savefig(sys.argv[1]+'_DataSent.png')

    plt.plot(flowDuration,bytesReceived,'ro')
    plt.title('BytesReceived vs Connection Time')
    plt.savefig(sys.argv[1]+'_DataReceived.png')

    plt.plot(bytesSent,bytesReceived,'ro')
    plt.title('BytesReceived vs BytesSent')
    plt.savefig(sys.argv[1]+'_DataReceived.png')

def main(argv):
    if len(argv) == 1:
        inputFile = argv[0]
        readCSVfile(inputFile)
    else:
        print "Invalid Command Line Arguments"
if __name__ == '__main__':
    main(sys.argv[1:])