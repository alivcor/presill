
import pcap
import math

numFlows = 0 #global MQTT flow counter
flow_buffer = [] #a global MQTT buffer containing (flow_id, Flow class object, flow state, numPacketsSent, numPacketsReceived, totalBytesSent, estRTT, mss, icwnd) tuples.
sent_buffer = []  # Sent MQTT containing all the packets information sent by sender, indexed by their flow ids and packet_id - (flow_id, packet_id, AAN, timestamp, pSize, seqNum)
ackd_buffer = [] # Sent MQTT Packets which have been acknowledged
received_buffer = [] # Received MQTT Packets containing all the packets received by sender, indexed by their flow ids and packet_ids - (flow_id, packet_id, AAN, TCPPacket)
retransmissions = {} #dict that records all retransmissions
end_ts = {} #dict that stores end timestamps of all flows

retransmissions_timeout = {}
retransmissions_fast = {}

winscale = {}

cwnd_sizes = []

def newFlow(tcp_packet):
    """
    Creates a new Flow class object, and adds it to the FlowBuffer (flow_id, Flow class object, flow state, numPacketsSent, numPacketsReceived) tuples.. Also updates the global flow counter
    :param flow: A flow class object
    :return: int value, flow id
    """
    global numFlows, flow_buffer, retransmissions, retransmissions_timeout, retransmissions_fast
    flow = Flow(tcp_packet)
    fid = numFlows+1
    flow_buffer.append([fid,flow,0,0,0,0,0,tcp_packet.MSSValue, tcp_packet.winSize, 10, tcp_packet.winSize, 0])  #(flow_id, Flow class object, flow state, numPacketsSent, numPacketsReceived, totalBytesSent, estRTT, mss, winsize, currentcwnd, ssthresh, congestion phase) tuples.
    retransmissions[fid] = 0
    retransmissions_timeout[fid] = 0
    retransmissions_fast[fid] = 0
    numFlows += 1
    # print "New Flow Registered with ID", str(fid)
    # printFlowBuffer()
    #add a key value pair to winscale
    return fid

def getFlowID(tcp_packet):
    """
    Returns the flow id for a given packet. If no matching flow is found in the flowbuffer, returns false
    :param tcp_packet: the tcp_packet class object that you want to get the flow id for
    :return: integer value, flow id
    """

    global numFlows, flow_buffer, sent_buffer, ackd_buffer, received_buffer, retransmissions, end_ts, retransmissions_timeout, retransmissions_fast
    port_set = {tcp_packet.sPort, tcp_packet.dPort}
    for flow in flow_buffer:
        if (port_set == set(flow[1].ports)):
            return flow[0]
    return False

def getFlowStateForPacket(tcp_packet):
    """
    This function returns the flow state for a given tcp packet.
    Flow States are defined as integer values as follows:
    0 - New Registered Flow (Only a SYN)
    1 - New Flow, In Handshake phase - SYN and SYN/ACK
    2 - Active Flow, Handshake Complete.
    3 - Sender FIN - ACKed
    4 - Receiver FIN - ACKed
    5 - Sender & Receiver both FIN ACKed - Only ACK is acceptable from now on. Rest is suspicious
    :param tcp_packet: A tcp packet class object
    :return: The flow state - integer value. False if no matching flow found for a given packet
    """

    global numFlows, flow_buffer, sent_buffer, ackd_buffer, received_buffer, retransmissions, end_ts, retransmissions_timeout, retransmissions_fast
    port_set = {tcp_packet.sPort, tcp_packet.dPort}
    for flow in flow_buffer:
        if (port_set == set(flow[1].ports)):
            return flow[2]
    return False

def fetchFlowDetails(flowID):
    """
    Returns the details about a Flow. Details include the flow id, Sender registered in the flow, and the receiver registered in the flow.
    :param tcp_packet: A TCPPacket class object
    :return: a list with [flow_id, senderPort, receiverPort]
    """

    global numFlows, flow_buffer, sent_buffer, ackd_buffer, received_buffer, retransmissions, end_ts, retransmissions_timeout, retransmissions_fast
    for flows in flow_buffer:
        if (flows[0] == flowID):
            flow_sPort = (flows[1].ports)[0]
            flow_dPort = (flows[1].ports)[1]
            flow_ts = flows[1].start_timestamp
            return [flowID, flow_sPort, flow_dPort, flow_ts]
    return False

def printFlowBuffer():
    """
    This is a helper function to print the entire contents of the flow buffer in a proper format on the console.
    :return: None
    """

    global numFlows, flow_buffer, sent_buffer, ackd_buffer, received_buffer, retransmissions, end_ts, retransmissions_timeout, retransmissions_fast
    print "---------------------------FLOW BUFFER--------------------------------"
    print "Total number of flows currently :", str(numFlows)
    for flow in flow_buffer:
        print "Flow", str(flow[0]), "from sPort:", str(flow[1].ports[0]), "to dPort:", str(flow[1].ports[1]), " - in state", str(flow[2]), " | numPacketsSent =", str(flow[3]), " | numPacketsReceived =", str(flow[4]), " | numBytesTransferred =", str(flow[5]), " | EstRTT =", str(flow[6]), " | MSS =", str(flow[7]), " | WinSize =", str(flow[8]), " | Current CWND =", str(flow[9]), " | Current ssthresh =", str(flow[10]), " | Congestion Phase =", str(flow[11])
    print "----------------------------------------------------------------------\n"

def updateFlowState(tcp_packet, new_state):
    """
    Updates the flow state to a new state for a particular tcp packet.
    :param tcp_packet: The TCPPacket class object for which the flow state has to be updated.
    :param new_state: The new state for the flow
    :return: True if a compatible flow found and state updation is successful. False otherwise.
    """

    global numFlows, flow_buffer, sent_buffer, ackd_buffer, received_buffer, retransmissions, end_ts, retransmissions_timeout, retransmissions_fast
    port_set = {tcp_packet.sPort, tcp_packet.dPort}
    for i in range(len(flow_buffer)):
        if (port_set == set(flow_buffer[i][1].ports)):
            curr_state = flow_buffer[i][2]
            if(new_state != curr_state):
                if(new_state > curr_state):
                    flow_buffer[i][2] = new_state
                    # print "Flow", str(flow_buffer[i][0]), "upgraded from State", str(curr_state), "to", str(new_state)
                    # printFlowBuffer()
                    return True
                else:
                    # print "State Degraded for flow", str(flow_buffer[i][0]), "!"
                    flow_buffer[i][2] = new_state
                    return True
    return False

def printAllFlows():
    """
    Prints the flow buffer in raw format. Use PrintFlowBuffer() instead.
    :return: None
    """
    global numFlows, flow_buffer
    print flow_buffer

def getTransDirection(tcp_packet):
    """
    Get Transmission Direction - Helper function that gets the direction of this tcp packet - sender to receiver (0) or receiver to sender (1)
    :param tcp_packet: A TCPPacket Class object
    :return: integer type - sender to receiver (0) or receiver to sender (1) - False if flow unmatched
    """

    global numFlows, flow_buffer, sent_buffer, ackd_buffer, received_buffer, retransmissions, end_ts, retransmissions_timeout, retransmissions_fast
    port_set = {tcp_packet.sPort, tcp_packet.dPort}
    for flow in flow_buffer:
        if (port_set == set(flow[1].ports)):
            if((flow[1].ports)[0] == tcp_packet.sPort and (flow[1].ports)[1] == tcp_packet.dPort):
                return 0
            else:
                return 1
    return False



def add_packet(tcp_packet, cnt, ts):
    """
    Adds a tcp packet indexed by its flow_id to the global transactions directory (SENT_BUFFER OR RECEIVED_BUFFER). Returns False if no matching flow found in the buffer
    :param tcp_packet: a TCPPacket class object
    :return: Packet ID of registered packet if successful. False otherwise
    """

    global numFlows, flow_buffer, sent_buffer, ackd_buffer, received_buffer, retransmissions, end_ts, retransmissions_timeout, retransmissions_fast
    port_set = {tcp_packet.sPort, tcp_packet.dPort}
    for i in range(0,len(flow_buffer)):
        flow = flow_buffer[i]
        if(port_set == set(flow[1].ports)):
            #if SYN and ACK, UPDATE MSS
            if(tcp_packet._SYN == 1 and tcp_packet._ACK == 1):
                flow_buffer[i][7] = tcp_packet.MSSValue
                flow_buffer[i][8] = tcp_packet.winSize
            #update the sent or receive buffers
            tDir = getTransDirection(tcp_packet)
            if(tDir == 0):
                # print " >> Packet added to sent buffer, with AAN =", str(tcp_packet.seqNum + max(1, tcp_packet.payloadLength))
                for sent_pkt in sent_buffer:
                    if(sent_pkt[0] == flow[0] and sent_pkt[2] == tcp_packet.seqNum + max(1, tcp_packet.payloadLength)):
                        #this is a retransmission
                        retransmissions[flow[0]] += 1

                        #check if it is due to timeout
                        if(tcp_packet.timestamp - sent_pkt[3] >= 2*flow[6]):
                            retransmissions_timeout[flow[0]] += 1

                        ackCount = 0
                        for recvd_pkt in received_buffer:
                            if (recvd_pkt[0] == flow[0] and recvd_pkt[6] == tcp_packet.seqNum):
                                ackCount += 1
                        if (ackCount >= 3):
                            # print "Triple Duplicate ACKs detected"
                            retransmissions_fast[flow[0]] += 1

                        # WE HAVE A LOSS - UPDATE
                        flow_buffer[i][10] = flow_buffer[i][9]/2
                        flow_buffer[i][9] = 10
                        flow_buffer[i][11] = 0
                        cwnd_sizes.append([flow[0], flow_buffer[i][9]])



                        break

                sent_buffer.append([flow[0], cnt, tcp_packet.seqNum + max(1, tcp_packet.payloadLength), tcp_packet.timestamp, tcp_packet.pSize, tcp_packet.seqNum, tcp_packet.ackNum])

                flow_buffer[i][3] += 1 #numSent

            elif(tDir == 1):
                # print " >> Packet added to received buffer, with AAN =", str(tcp_packet.seqNum + max(1, tcp_packet.payloadLength))
                if(tcp_packet._ACK == 1):
                    #This is ack packet. Remove the matching packet from sent buffer and add it to the acked buffer
                    for sent_pkt in sent_buffer:
                        if(sent_pkt[0] == flow[0] and sent_pkt[2] <= tcp_packet.ackNum):
                            #sent_pkt[2] is the AAN
                            # print "Sent Packet with Seq No", str(sent_pkt[5]), " acknowledged."
                            SampleRTT = ts - sent_pkt[3]
                            # print "SampleRTT : ", SampleRTT,
                            if(flow_buffer[i][6] == 0):
                                flow_buffer[i][6] = SampleRTT
                            else:
                                flow_buffer[i][6] = 0.875 * flow_buffer[i][6] + 0.125*SampleRTT #EstRTT

                            if(flow_buffer[i][11] == 0): #check if it is in slow start phase

                                if(flow_buffer[i][9] >= flow_buffer[i][10]): # current cwnd is greater than ssthresh
                                    #GO TO CONGESTION AVOIDANCE PHASE
                                    flow_buffer[i][11] = 1
                                else:
                                    flow_buffer[i][9] = 2 * flow_buffer[i][9]  # UPDATE CWND
                                    cwnd_sizes.append([flow[0], flow_buffer[i][9]])
                            else:
                                #we're in congestion avoidance phase
                                flow_buffer[i][9] += 1/flow_buffer[i][9]
                                cwnd_sizes.append([flow[0], flow_buffer[i][9]])


                            # print " |  EstRTT : ", flow_buffer[i][6]
                            sent_buffer.remove(sent_pkt)
                            ackd_buffer.append(sent_pkt)
                            flow_buffer[i][5] += sent_pkt[4] #TODO :CHANGE TO pSize #for getting total size of packets sent after iteration ends
                received_buffer.append([flow[0], cnt, tcp_packet.seqNum + max(1, tcp_packet.payloadLength), tcp_packet.timestamp, tcp_packet.pSize, tcp_packet.seqNum, tcp_packet.ackNum])
                flow_buffer[i][4] += 1 #numReceived
            else:
                raise Exception("Invalid Direction !")
            return flow_buffer[i][3] + flow_buffer[i][4]
    return False




class Flow():
    """
    This is the general class for all flows. A TCP flow starts with a TCP SYN and ends at a TCP FIN
    """
    global numFlows, flow_buffer
    def __init__(self, tcp_packet):
        self.ports = [tcp_packet.sPort, tcp_packet.dPort]
        self.start_timestamp = tcp_packet.timestamp


def decimalize(barry):
    """
    Super helper function - sorts out just everything ! Basically, it takes a byte array and turns it into a base 10 integer. Sounds superb, right ? Why doesn't python have an inbuilt function for that ?
    :param barry: a byte array that you want to convert to base 10
    :return: a base 10 integer !
    """
    mds = "" #my decimal string
    for byte_v in barry:
        hex_v = hex(byte_v)[2:]
        if(len(hex_v) == 0):
            hex_v = "00"
        elif(len(hex_v) == 1):
            hex_v = "0" + hex_v
        else:
            # we're good
            pass
        mds = mds + hex_v
    return int(mds, base=16)




class TCPPacket:
    """
    This is the class that defines a TCPPacket object
    """
    def __init__(self, tcp_packet, ts, tfs):
        self.timestamp = ts
        self.sPort = decimalize(tcp_packet[0:2]) #+1/8 - 1
        self.dPort = decimalize(tcp_packet[2:4])
        self.seqNum = decimalize(tcp_packet[4:8])
        self.ackNum = decimalize(tcp_packet[8:12])

        b1 = int(bin(int(hex(tcp_packet[12]), base=16)), base=2) #data and offset
        b2 = int(bin(int(hex(tcp_packet[13]), base=16)), base=2) #flags

        mask_reserved = 0b00001111
        mask_dataOff = 0b11110000
        dataoffset = ((mask_dataOff & b1) >> 4) * 4
        self.dataOff = ((mask_dataOff & b1) >> 4) * 4
        self.reserved = mask_reserved & b1


        self._CWR = (0b10000000 & b2) >> 7
        self._ECE = (0b01000000 & b2) >> 6
        self._URG = (0b00100000 & b2) >> 5
        self._ACK = (0b00010000 & b2) >> 4
        self._PSH = (0b00001000 & b2) >> 3
        self._RST = (0b00000100 & b2) >> 2
        self._SYN = (0b00000010 & b2) >> 1
        self._FIN = 0b00000001 & b2

        self.winSize = decimalize(tcp_packet[14:16])
        self.chkSum = decimalize(tcp_packet[16:18])
        self.urgPointer = decimalize(tcp_packet[18:20])
        self.others = tcp_packet[24:]
        self.MSSKind = int(hex(tcp_packet[20]), base=16)
        self.MSSLength = int(hex(tcp_packet[21]), base=16)
        self.MSSValue = decimalize(tcp_packet[22:24])
        self.pSize = len(tcp_packet)
        self.payloadLength = len(tcp_packet) - dataoffset
        self.totalFrameSize = tfs
        if(self._SYN == 1 and self._ACK == 1):
            self.winscale = int(hex(tcp_packet[39]), base=16)


    def get_flags(self):
        """
        Helper function to return the flags value in boolean 0/1 values.
        :return: a list of 8 flags, each of boolean type
        """
        return [self._CWR, self._ECE, self._URG, self._ACK, self._PSH, self._RST, self._SYN, self._FIN]

def get_tcp_packet(pkt, ts):
    """
    The function takes a raw packet, and extracts the TCP Packet out of it. (Discards the Ethernet and IP headers)
    :param pkt: The raw packet with ethernet and IP headers
    :param ts: Timestamp of teh packet
    :return: A TCPPacket class object, TCP Packet
    """
    eth_packet = bytearray(pkt)
    return TCPPacket(eth_packet[34:], ts, len(pkt))

#
# def print_first_two_trans():
#     max_count = {}
#     for transaction in transaction_record:
#         flow_id = transaction[0]
#         try:
#             if(max_count[flow_id] < 6):
#                 print "Flow :", str(transaction[0]), "| Packet Number :", str(transaction[1]), "| Sequence Number :", str(transaction[2]), "| Ack Number :", str(transaction[3]), "| Window Size Number :", str(transaction[4])
#                 max_count[flow_id] += 1
#         except KeyError:
#             max_count[flow_id] = 1

def updateFlowWinSize(tcp_packet):
    global flow_buffer
    fid = getFlowID(tcp_packet)
    for i in range(0, len(flow_buffer)):
        flow = flow_buffer[i]
        if (flow[0] == fid):
            flow_buffer[i][8] = int(tcp_packet.winSize * math.pow(2,winscale[fid]))
            break

def capture_flow(pkt_hist):
    """
    Monitors the flow in the file.
    :param pkt_hist: a list of raw eth packets
    :return: 0 (No errors)
    """
    closedby = []

    global numFlows, flow_buffer, sent_buffer, ackd_buffer, received_buffer, retransmissions, end_ts, retransmissions_timeout, retransmissions_fast
    # print "Starting capture"
    cnt = 0
    for ts, pkt in pkt_hist:
        cnt+=1
        # print "PACKET -----" + str(cnt)
        tcp_packet = get_tcp_packet(pkt, ts)

        # print "Seq Num :", str(tcp_packet.seqNum), "| Ack Num :", tcp_packet.ackNum, "| Packet Size :", tcp_packet.pSize, "| Payload Length :", tcp_packet.payloadLength

        fState = getFlowStateForPacket(tcp_packet)
        if(fState == 2):
            #This means that the flow is in active state
            # print "Packet belongs to Flow", str(getFlowID(tcp_packet)), "which is already in ACTIVE state."
            pkt_id = add_packet(tcp_packet, cnt, ts)
            if (tcp_packet._FIN == 1 and getTransDirection(tcp_packet) == 0):
                updateFlowState(tcp_packet, 3)
                closedby.append([getFlowID(tcp_packet), cnt, "SENDERCLOSE"])
                # FIN ACKed by sender
            if(tcp_packet._FIN == 1 and getTransDirection(tcp_packet) == 1):
                updateFlowState(tcp_packet, 4)
                closedby.append([getFlowID(tcp_packet), cnt, "RECVRCLOSE"])
                # FIN ACKed by server
        elif(fState == 3):
            pkt_id = add_packet(tcp_packet, cnt, ts)
            if (tcp_packet._FIN == 1 and getTransDirection(tcp_packet) == 1):
                updateFlowState(tcp_packet, 5)
                closedby.append([getFlowID(tcp_packet), cnt, "RECVRCLOSE"])
                # Was in 3 state (finned by sender). Now also FIN ACKed by server
        elif(fState == 4):
            pkt_id = add_packet(tcp_packet, cnt, ts)
            if (tcp_packet._FIN == 1 and getTransDirection(tcp_packet) == 0):
                updateFlowState(tcp_packet, 5)
                closedby.append([getFlowID(tcp_packet), cnt, "SENDERCLOSE"])
                # Was in 4 state (finned by server). Now also FIN ACKed by sender
        elif(fState == 5):
            if(tcp_packet._ACK == 1):
                # Just a stupid ack
                add_packet(tcp_packet, cnt, ts)
                end_ts[getFlowID(tcp_packet)] = ts
            else:
                print "Suspicious Packet."
                print(closedby)
                printFlowBuffer()
                break
        else:
            if(tcp_packet._SYN == 1 and tcp_packet._ACK == 0):
                # print "Flow initiated with timestamp", ts
                fid = newFlow(tcp_packet)
                # updateFlowState(fid, 0) NO NEED TO DO THAT, WHEN WE CREATE A NEW FLOW, ITS DEFAULT STATE IS 0
            if(tcp_packet._SYN == 1 and tcp_packet._ACK == 1):
                # print "Flow SYN/ACK Received"
                updateFlowState(tcp_packet, 1)
                winscale[getFlowID(tcp_packet)] = tcp_packet.winscale
            if (tcp_packet._SYN == 0 and tcp_packet._ACK == 1):
                'TODO : IN THIS CASE WE NEED TO CHECK IF IT IS FOR NORMAL ACK OR HANDSHAKE ACK'
                updateFlowState(tcp_packet, 2)
                updateFlowWinSize(tcp_packet)
            pkt_id = add_packet(tcp_packet, cnt, ts)
        # print "Sent Buffer Length : ", len(sent_buffer), " | Received Buffer Length : ", len(received_buffer), " | Acked Buffer Length : ", len(ackd_buffer)
        # printFlowBuffer()
        # print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n\n"
        if(pkt_id == False):
            print " >> No TCP Flow registered for this packet with timestamp", ts
            break

    # print_first_two_trans()
    # print closedby
    return 0


def count_flows(pkt_hist):
    """
    Counts the number of flows in a given packet transfer sequence.
    :param pkt_hist:
    :return: an integer value for the number of flows.
    """
    cnt = 0
    for ts, pkt in pkt_hist:
        tcp_packet = get_tcp_packet(pkt, ts)
        if(tcp_packet._SYN == 1 and tcp_packet._ACK == 0):
            print ts
            cnt+=1
    return cnt



def count_lost_packets():
    global sent_buffer, retransmissions
    total_lost = {}
    for pkt in sent_buffer:
        try:
            total_lost[pkt[0]] += 1
        except KeyError:
            total_lost[pkt[0]] = -1
             # NOT 1 - WE HAVE TO ACCOMMODATE FOR THE ACK FOR FIN/ACK
    for fid in retransmissions:
        total_lost[fid] += retransmissions[fid]
    return total_lost


def count_total_time():
    global flow_buffer, end_ts
    total_time = {}
    for flow in flow_buffer:
        total_time[flow[0]] = end_ts[flow[0]] - flow[1].start_timestamp
    return total_time

def get_empirical_tput(tbs, ttime):
    """
    Returns the empirical throughput
    :param tbs: total bytes sent for each flow as a dict
    :param ttime: total time for a session for each flow as a dict
    :return: a dict type containing all flow ids with their emp throughputs
    """
    etput = {}
    for l in tbs:
        etput[l] = (tbs[l]*8)/(ttime[l]*1000*1000)
    return etput

def get_total_bytes_sent():
    global flow_buffer
    tbs = {}
    for flow in flow_buffer:
        tbs[flow[0]] = flow[5]

    return tbs

def get_loss_rates(tlp):
    global flow_buffer
    lrates = {}
    for flow in flow_buffer:
        fid = flow[0]
        lrates[fid] = float(tlp[fid])/float(flow[3])
    return lrates

def get_theory_tput(p):
    global flow_buffer
    thtput = {}
    for flow in flow_buffer:
        fid = flow[0]
        try:
            thtput[fid] = (float(flow[7])*math.sqrt(3/2)*8)/(float(flow[6])*math.sqrt(p[fid])*1000*1000)
        except ZeroDivisionError:
            thtput[fid] = (float(flow[8])*8)/(float(flow[6])*1000*1000) #icwnd/rtt
    return thtput

def get_win_size_for_flow(fid):
    global flow_buffer
    for flow in flow_buffer:
        if(flow[0] == fid):
            return flow[8]
    return False

def get_first_five_cwnd_sizes():
    global cwnd_sizes
    max_up = {}
    ret_sizes = []
    for cfu in cwnd_sizes:
        #cfu = cwind flow update
        try:
            max_up[cfu[0]] += 1
        except KeyError:
            max_up[cfu[0]] = 1
        if(max_up[cfu[0]] < 6):
            ret_sizes.append(cfu)
    return ret_sizes

def printFirstTwoTrans(ackd,rcvd):
    max_count_sent = {}
    for sent_packet in ackd:
        fid = sent_packet[0]
        try:
            mcs = max_count_sent[fid]
            max_count_sent[fid] += 1
        except:
            max_count_sent[fid] = 1
            mcs = 1
        if(mcs > 3 and mcs < 6):
            fdet = fetchFlowDetails(fid)
            print ">> Flow", str(fid), "From", str(fdet[1]), "To", str(fdet[2]), "- Seq Num:", str(sent_packet[5]), "| Ack Num:", str(sent_packet[6]), "| Receive Window size :", str(get_win_size_for_flow(fid))
            #find corresponding ack in rcvd and print
            for rcvd_packet in rcvd:
                if(rcvd_packet[6] == sent_packet[2]):
                    print ">> Flow", str(fid), "From", str(fdet[2]), "To", str(fdet[1]), "- (ACK) -Seq Num:", str(
                        rcvd_packet[5]), "| Ack Num:", str(rcvd_packet[6]), "| Receive Window size :", str(
                        get_win_size_for_flow(fid))


pkt_hist = pcap.pcap('assignment2.pcap')
# print count_flows(pkt_hist)
capture_flow(pkt_hist)
# print "--------------------------------------------------"
printFlowBuffer()
# printFirstTwoTrans(ackd_buffer, received_buffer)
# print "-----"
# print received_buffer[0:5]
# for i in sent_buffer:
#     print i
# print "RETRANSMISSIONS : ",
# print retransmissions
# print "TOTAL LOST PACKETS : ",
# tlp = count_lost_packets()
# print tlp
# print "TOTAL BYTES SENT : ",
# tbs = get_total_bytes_sent()
# print tbs
# print "TOTAL TIME : ",
# ttime = count_total_time()
# print ttime
# print "EMPIRICAL THROUGHPUT : ",
# print get_empirical_tput(tbs, ttime)
# print "LOSS RATES : ",
# tlr = get_loss_rates(tlp)
# print tlr
# for f in flow_buffer:
#     print "RTT FOR ", str(f[0]), " is ", str(f[6])
# print "THEORETICAL THROUGHPUT : ",
# print get_theory_tput(tlr)

ffcs = get_first_five_cwnd_sizes()

print "FIRST FIVE COMMAND WINDOW SIZES FOR FLOWS : "

print "Initialized at 10"
for flow in ffcs:
    print "Flow", str(flow[0]), " - CWND =", str(flow[1])

print "LOSS/RETRANSMISSION DUE TO TIMEOUT : ", retransmissions_timeout
print "LOSS/RETRANSMISSION DUE TO TRIPLE DUP ACK : ", retransmissions_fast
