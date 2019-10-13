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
                    if port == '2313':
                        print "dddd------",info
                    record = {'SrcPort':port,'DestIP':dst,'Start':time,'End':-1, 'BytesSent':length, 'BytesReceived':0, 'ServerSeq':[], 'ClientAcks':[]}
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
                    temp = info.split(' Ack=')
                    temp1 = temp[1]
                    ackNum = temp1.split(' ')
                    #print("ackNum: ",ackNum[0])
                    for i in range(len(tcpFlows[counter])):
                        rec = tcpFlows[counter][i]
                        if(port=='2313'):
                            print time,info,rec['End'],rec['ClientAcks']
                        if(rec['SrcPort']==port and rec['End']==-1): #Please check me
                            rec['ClientAcks'].append((time,ackNum[0]))    #########Added
                            rec['BytesSent'] = rec['BytesSent']+length
                            tcpFlows[counter][i] = rec
            elif(srcIP==dst):           #Packets sent from server to the client
                if(protocol=='TCP' and info.find('[ACK]')>-1):
                    temp = info.split(" ") #2313  >  21 [ACK] Seq=3876923932 Ack=3562637065 Win=17520 Len=0
                    port = temp[4]         #2313  >  21 [ACK] Seq=3876923948 Ack=3562637141 Win=16205 Len=0 -1
                    temp1 = info.split(' Seq=')
                    temp2 = temp1[1]
                    seqNum = temp2.split(' ')
                    for i in range(len(tcpFlows[counter])):
                        rec = tcpFlows[counter][i]
                        if(rec['SrcPort']==port and rec['End']==-1):
                            rec['ServerSeq'].append((time,seqNum[0]))
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
    dupAckFlows(tcpFlows)
    outOfOrder(tcpFlows)
    timeout(tcpFlows)
    numFlows(tcpFlows)
    connectionDuration(tcpFlows)
    dataTransferred(tcpFlows)
    traffic(tcpFlows)
    retransmissions(tcpFlows)
    #fun(tcpFlows,'3362','131.243.2.12')

def plotGraph(flow,str):
    l1,l2 = flow['ServerSeq'],flow['ClientAcks']
    list1,list2,list3,list4 = [],[],[],[]
    for x in l1:
        list1.append(x[0])
        list2.append(x[1])
    for y in l2:
        list3.append(y[0])
        list4.append(y[1])
    plt.scatter(list1,list2,color='red')  #Red indicates Sequence numbers
    plt.scatter(list3,list4,color='blue') #Blue indicates Ack Numbers
    plt.savefig(sys.argv[1]+str)
    plt.close()

def timeout(tcpFlows):
    res = []
    for flowList in tcpFlows:
        for flow in flowList:
            flag = False
            seqList = flow['ServerSeq']
            ackList = flow['ClientAcks']
            for ack in ackList:
                for i in range(len(seqList)-1):
                    seq1Time,seq2Time,ackTime = (seqList[i])[0],(seqList[i+1])[0],ack[0]
                    seq1No,seq2No,ackNo = int((seqList[i])[1]),int((seqList[i+1])[1]),int(ack[1])
                    if seq1No<=seq2No and ackNo>seq2No and seq1Time<=ackTime and ackTime<=seq2Time:
                        #print(ackNo,seq1No,seq2No)
                        #print(ackTime,seq1Time,seq2Time)
                        flag = True
            if flag==True:
                res.append(flow)
    flow1 = res[len(res)-1]
    flow2 = res[len(res)-2]
    plotGraph(flow1,'spurious1.png')
    plotGraph(flow2,'spurious2.png')
    print "# of timeout flows: ",len(res)

 
def dupAckFlows(tcpFlows):
    res = []
    for flowList in tcpFlows:
        for flow in flowList:
            flag = False
            seqList = flow['ServerSeq']
            ackList = flow['ClientAcks']
            for ack in ackList:
                for seq in seqList:
                    ackTime,seqTime = ack[0],seq[0]
                    if int(ack[1])<int(seq[1]) and ackTime>seqTime:
                        flag = True
            if flag == True:
                res.append(flow)
    flow1 = res[len(res)-1]
    flow2 = res[len(res)-2]
    plotGraph(flow1,'dupAck1.png')
    plotGraph(flow2,'dupAck2.png')
    print(flow2['ServerSeq'],flow2['ClientAcks'])
    print "# of dup ack flows: ",len(res)

def outOfOrder(tcpFlows):
    res = []
    for flowList in tcpFlows:
        for flow in flowList:
            flag = False
            seqList = flow['ServerSeq']
            ackList = flow['ClientAcks']
            for seq in seqList:
                for i in range(len(ackList)-1):
                    ack1Time,ack2Time,seqTime = (ackList[i])[0],(ackList[i+1])[0],seq[0]
                    ack1No,ack2No,seqNo = int((ackList[i])[1]),int((ackList[i+1])[1]),int(seq[1])
                    if ack1No<seqNo and seqNo<ack2No and seqTime<ack1Time and ack1Time<ack2Time:
                        flag = True
            if flag == True:
                res.append(flow)
    flow1 = res[len(res)-1]
    flow2 = res[len(res)-2]
    plotGraph(flow1,'outOfOrder1.png')
    plotGraph(flow2,'outOfOrder2.png')
    print "# of outOfOrder flows: ",len(res)

def retransmissions(tcpFlows):
    res = []
    for flowList in tcpFlows:
        for flow in flowList:
            flag = False
            seqList = flow['ServerSeq']
            seqList.sort(key = lambda x : int(x[1]))
            #print(seqList)
            for i in range(len(seqList)-1):
                seq1 = seqList[i]
                seq2 = seqList[i+1]
                if(seq1[1]==seq2[1]):
                    flag = True
            if flag==True:
                res.append(flow)
    l1 = res[len(res)/2]
    l2 = res[1+(len(res)/2)]
    plotGraph(l1,'retransmission1.png')
    plotGraph(l2,'retransmission2.png')
    print "# of retransmission flows: ",len(res)

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
    plt.close()
    #plt.show()

def connectionDuration(tcpFlows):
    flowtime = []
    for flowList in tcpFlows:
        for flow in flowList:
            if(flow['End']!=-1):
                duration = (flow['End']-flow['Start'])/60       # duration is in seconds
                flowtime.append(duration)
    flowtime.sort()
    #print(flowtime)
    probability = []
    flowtime = [x*60 for x in flowtime]
    totalFlows = len(flowtime)
    end = flowtime[totalFlows-1]
    for i in range(totalFlows):
        probability.append(((i+1)*1.0)/totalFlows)
    plt.plot(flowtime,probability)
    plt.title('# of Connections vs Connection Time')
    plt.savefig(sys.argv[1]+'connectionTime.png')
    plt.close()
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
    plt.close()

    plt.plot(flowDuration,bytesReceived,'ro')
    plt.title('BytesReceived vs Connection Time')
    plt.savefig(sys.argv[1]+'_DataReceived.png')
    plt.close()

    plt.plot(bytesSent,bytesReceived,'ro')
    plt.title('BytesReceived vs BytesSent')
    plt.savefig(sys.argv[1]+'_DataReceived.png')
    plt.close()

def fun(tcpFlows,src,dst):
    for flowList in tcpFlows:
        for flow in flowList:
            if(flow['SrcPort']==src and flow['DestIP']==dst):
                print flow['ClientAcks']
                print flow['ServerSeq']

def main(argv):
    if len(argv) == 1:
        inputFile = argv[0]
        readCSVfile(inputFile)
    else:
        print "Invalid Command Line Arguments"
if __name__ == '__main__':
    main(sys.argv[1:])

"""def dupAckFlows(tcpFlows):
    res = []
    for flowList in tcpFlows:
        for flow in flowList:
            flag = False
            ackList = flow['ClientAcks']
            ackList.sort(key = lambda x : int(x[1]))
            for i in range(len(ackList)-1):
                ack1 = ackList[i]
                ack2 = ackList[i+1]
                if(ack1[1] == ack2[1]):
                    flag = True
            if flag==True:
                res.append(flow)
    print 'Number of duplicate ack flows',len(res)
    print 'First Ack Flow',(tcpFlows[0][0])['ClientAcks']"""
#5757  >  21 [ACK] Seq=3278704724 Ack=4171167646 Win=17130 Len=0
"""def ackCorruption(tcpFlows):
    res = []
    for flowList in tcpFlows:
        for flow in flowList:
            flag = False
            seqList = flow['ServerSeq']
            ackList = flow['ClientAcks']
            for ack in ackList:
                for i in range(len(seqList)-1):
                    seq1Time,seq2Time,ackTime = (seqList[i])[0],(seqList[i+1])[0],ack[0]
                    seq1No,seq2No,ackNo = int((seqList[i])[1]),int((seqList[i+1])[1]),int(ack[1])
                    if seq1No<=ackNo and seq2No<=ackNo and seq1Time<=ackTime and ackTime<=seq2Time:
                        flag = True
            if flag==True:
                res.append(flow)
    print "# of timeout flows: ",len(res)

def isSpurious(seqList,ackList):
    data = {}
    flag = False
    for seq in seqList:
        data[seq[1]] = False
    for ack in ackList:
        if ack[1] in data:
            if data[ack[1]]==True:
                flag = True
                print ack[1]
            else:
                data[ack[1]]=True
        else:
            print 'Hey'
    return flag"""