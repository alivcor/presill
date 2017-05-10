import pcap
import math

numFlows = 0 #global flow counter
flow_buffer = [] #a global buffer containing (flow_id, Flow class object, flow state, numPacketsSentByClient, numPacketsReceivedByClient, totalBytesSent, estRTT, mss, icwnd) tuples.

client_sent = []  # SENT PACKETS DIRECTORY containing all the packets information sent by client but not necessarily acked by server, indexed by their flow ids and packet_id - (flow_id, packet_id, AAN, timestamp, pSize, seqNum, http_packet)
server_received = [] # SENT Packets by client which have been acknowledged by server
server_sent = [] # Packets sent by server but not acknowledged by client containing all the packets received by sender, indexed by their flow ids and packet_ids - (flow_id, packet_id, AAN, pSize, seqNum, http_packet)
client_received = [] #Packets received by client (acked from server_sent)
# all have format - (flow_id, packet_id, AAN, timestamp, pSize, seqNum, http_packet)

retransmissions = {} #dict that records all retransmissions
end_ts = {} #dict that stores end timestamps of all flows
last_push_ts = 0





def reset_all_vars():
    global numFlows, flow_buffer, client_sent, server_received, server_sent, client_received, retransmissions, end_ts, start_ts, page_load_begin, page_load_end, page_load_time, last_push_ts, totalByteSize, totalByteSizeforflow
    numFlows = 0  # global flow counter
    flow_buffer = []  # a global buffer containing (flow_id, Flow class object, flow state, numPacketsSentByClient, numPacketsReceivedByClient, totalBytesSent, estRTT, mss, icwnd) tuples.

    client_sent = []  # SENT PACKETS DIRECTORY containing all the packets information sent by client but not necessarily acked by server, indexed by their flow ids and packet_id - (flow_id, packet_id, AAN, timestamp, pSize, seqNum, http_packet)
    server_received = []  # SENT Packets by client which have been acknowledged by server
    server_sent = []  # Packets sent by server but not acknowledged by client containing all the packets received by sender, indexed by their flow ids and packet_ids - (flow_id, packet_id, AAN, pSize, seqNum, http_packet)
    client_received = []  # Packets received by client (acked from server_sent)
    # all have format - (flow_id, packet_id, AAN, timestamp, pSize, seqNum, http_packet)

    retransmissions = {}  # dict that records all retransmissions
    end_ts = {}  # dict that stores end timestamps of all flows
    start_ts = {}
    page_load_begin = float("inf")
    page_load_end = 0
    page_load_time = 0
    last_push_ts = 0
    totalByteSize = 0
    totalByteSizeforflow = 0
    return True




def newFlow(tcp_packet):
    """
    Creates a new Flow class object, and adds it to the FlowBuffer (flow_id, Flow class object, flow state, numPacketsSent, numPacketsReceived) tuples.. Also updates the global flow counter
    :param flow: A flow class object
    :return: int value, flow id
    """
    global numFlows, flow_buffer, client_sent, server_received, server_sent, client_received, retransmissions, end_ts
    flow = Flow(tcp_packet)
    fid = numFlows+1
    flow_buffer.append([fid,flow,0,0,0,0,0,0,0,0,tcp_packet.MSSValue, tcp_packet.winSize])  #(flow_id, Flow class object, flow state, numPacketsSent, numPacketsReceived, totalBytesSent, estRTT, mss, icwnd) tuples.
    retransmissions[fid] = 0
    numFlows += 1
    # print "New Flow Registered with ID", str(fid)
    # printFlowBuffer()
    return fid


def getFlowID(tcp_packet):
    """
    Returns the flow id for a given packet. If no matching flow is found in the flowbuffer, returns false
    :param tcp_packet: the tcp_packet class object that you want to get the flow id for
    :return: integer value, flow id
    """
    global numFlows, flow_buffer, client_sent, server_received, server_sent, client_received, retransmissions, end_ts
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
    global numFlows, flow_buffer, client_sent, server_received, server_sent, client_received, retransmissions, end_ts
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
    global numFlows, flow_buffer, client_sent, server_received, server_sent, client_received, retransmissions, end_ts
    for flows in flow_buffer:
        if (flows[0] == flowID):
            flow_sPort = (flows[1].ports)[0]
            flow_dPort = (flows[1].ports)[1]
            flow_ts = flows[1].start_timestamp
            return [flowID, flow_sPort, flow_dPort, flow_ts]
    return False

def printFlowBuffer():
    """
    This is a helper function to # print the entire contents of the flow buffer in a proper format on the console.
    :return: None
    """
    global numFlows, flow_buffer, client_sent, server_received, server_sent, client_received, retransmissions, end_ts
    print "---------------------------FLOW BUFFER--------------------------------"
    print "Total number of flows currently :", str(numFlows)
    for flow in flow_buffer:
        print "Flow", str(flow[0]), "from sPort:", str(flow[1].ports[0]), "to dPort:", str(flow[1].ports[1]), " - in state", str(flow[2]), " | numPacketsSentByClient =", str(flow[3]), " | numPacketsSentByServer =", str(flow[4]), " | numPacketsReceivedByClient =", str(flow[5]), " | numPacketsReceivedByServer =", str(flow[6]), " | numBytesSentByClient =", str(flow[7]), " | numBytesSentByServer =", str(flow[8]), " | EstRTT =", str(flow[9]), " | MSS =", str(flow[10]), " | iCWND =", str(flow[11])
    print "----------------------------------------------------------------------\n"

def updateFlowState(tcp_packet, new_state):
    """
    Updates the flow state to a new state for a particular tcp packet.
    :param tcp_packet: The TCPPacket class object for which the flow state has to be updated.
    :param new_state: The new state for the flow
    :return: True if a compatible flow found and state updation is successful. False otherwise.
    """
    global numFlows, flow_buffer, client_sent, server_received, server_sent, client_received, retransmissions, end_ts
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


def updateFlowTS(tcp_packet, ts):
    """
    Upon connection establishment, (Flow becoming ACTIVE), updates the flow timestamp to indicate the actual time when handshake was completed and flow became active
    :param tcp_packet: the tcp_packet corresponding to that flow
    :param ts: the timestamp of that tcp_packet
    :return: True if success, False otherwise
    """
    global numFlows, flow_buffer, client_sent, server_received, server_sent, client_received, retransmissions, end_ts
    port_set = {tcp_packet.sPort, tcp_packet.dPort}
    for i in range(len(flow_buffer)):
        if (port_set == set(flow_buffer[i][1].ports)):
            flow_buffer[i][1].start_timestamp = ts
            return True
    return False


def printAllFlows():
    """
    Prints the flow buffer in raw format. Use PrintFlowBuffer() instead.
    :return: None
    """
    global numFlows, flow_buffer
    # print flow_buffer

def getTransDirection(tcp_packet):
    """
    Get Transmission Direction - Helper function that gets the direction of this tcp packet - sender to receiver (0) or receiver to sender (1)
    :param tcp_packet: A TCPPacket Class object
    :return: integer type - sender to receiver (0) or receiver to sender (1) - False if flow unmatched
    """
    global numFlows, flow_buffer, client_sent, server_received, server_sent, client_received, retransmissions, end_ts
    port_set = {tcp_packet.sPort, tcp_packet.dPort}
    for flow in flow_buffer:
        if (port_set == set(flow[1].ports)):
            if((flow[1].ports)[0] == tcp_packet.sPort and (flow[1].ports)[1] == tcp_packet.dPort):
                return 0
            else:
                return 1
    return False



def add_packet(tcp_packet, http_packet, cnt, ts):
    """
    Adds a tcp packet indexed by its flow_id to the global transactions directory (SENT_BUFFER OR RECEIVED_BUFFER). Returns False if no matching flow found in the buffer
    :param tcp_packet: a TCPPacket class object
    :return: Packet ID of registered packet if successful. False otherwise
    """
    global numFlows, flow_buffer, client_sent, server_received, server_sent, client_received, retransmissions, end_ts
    port_set = {tcp_packet.sPort, tcp_packet.dPort}
    for i in range(0,len(flow_buffer)):
        flow = flow_buffer[i]
        if(port_set == set(flow[1].ports)):
            #if SYN and ACK, UPDATE MSS
            if(tcp_packet._SYN == 1 and tcp_packet._ACK == 1):
                flow_buffer[i][10] = tcp_packet.MSSValue
                flow_buffer[i][11] = tcp_packet.winSize
            #update the sent or receive buffers
            tDir = getTransDirection(tcp_packet)
            if(tDir == 0):
                # CLIENT TO SERVER
                #Two cases - it is an ACK (Client saying to server that it has received something server sent, or the client is actually sending a request
                if(tcp_packet._ACK == 1):
                    # Client is sending an ACK to server
                    # TODO : Move packets from server_sent to client_received
                    # print " >> Moving a packet from server_sent to client_received, with AAN =", str(tcp_packet.seqNum + max(1, tcp_packet.payloadLength))
                    # This is ack packet. Remove the matching packet from sent buffer and add it to the acked buffer
                    for sent_pkt in server_sent:
                        if (sent_pkt[0] == flow[0] and sent_pkt[2] <= tcp_packet.ackNum):
                            # sent_pkt[2] is the AAN
                            # print "Server Sent Packet with Seq No", str(sent_pkt[5]), " acknowledged."
                            SampleRTT = ts - sent_pkt[3]
                            # print "SampleRTT : ", SampleRTT,
                            if (flow_buffer[i][9] == 0): #FLOW_BUFFER[i][9] is estRTT
                                flow_buffer[i][9] = SampleRTT
                            else:
                                flow_buffer[i][9] = 0.875 * flow_buffer[i][9] + 0.125 * SampleRTT  # EstRTT
                            # print " |  EstRTT : ", flow_buffer[i][9]
                            server_sent.remove(sent_pkt)
                            client_received.append(sent_pkt)
                            flow_buffer[i][8] += sent_pkt[4] #UPDATE BYTES SENT BY SERVER # TODO :CHANGE TO pSize #for getting total size of packets sent after iteration ends
                            flow_buffer[i][5] += 1 #UPDATE NUMBER OF PACKETS RECEIVED BY CLIENT

                if(tcp_packet.payloadLength > 0):
                    # print " >> Also contains HTTP Packet - Packet being added to client_sent buffer, with AAN =", str(tcp_packet.seqNum + max(1, tcp_packet.payloadLength))
                    #check if it is retransmission
                    for sent_pkt in client_sent:
                        if(sent_pkt[0] == flow[0] and sent_pkt[2] == tcp_packet.seqNum + max(1, tcp_packet.payloadLength)):
                            #this is a retransmission
                            retransmissions[flow[0]] += 1
                    client_sent.append([flow[0], cnt, tcp_packet.seqNum + max(1, tcp_packet.payloadLength), tcp_packet.timestamp, tcp_packet.pSize, tcp_packet.seqNum, http_packet, tcp_packet.ackNum])
                flow_buffer[i][3] += 1 #numPKTSSentByClient

            elif(tDir == 1):
                # SERVER TO CLIENT
                if(tcp_packet._ACK == 1):
                    # SERVER IS SENDING AN ACK TO CLIENT
                    # MOVE A PACKET FROM CLIENT_SENT TO SERVER_RECEIVED
                    # print " >> Moving a packet from client_sent to server_received, with AAN =", str(tcp_packet.seqNum + max(1, tcp_packet.payloadLength))
                    #This is ack packet. Remove the matching packet from sent buffer and add it to the acked buffer
                    for sent_pkt in client_sent:
                        if(sent_pkt[0] == flow[0] and sent_pkt[2] <= tcp_packet.ackNum):
                            #sent_pkt[2] is the AAN
                            # print "Client Sent Packet with Seq No", str(sent_pkt[5]), " acknowledged."
                            SampleRTT = ts - sent_pkt[3]
                            # print "SampleRTT : ", SampleRTT,
                            if(flow_buffer[i][9] == 0):
                                flow_buffer[i][9] = SampleRTT
                            else:
                                flow_buffer[i][9] = 0.875 * flow_buffer[i][9] + 0.125*SampleRTT #EstRTT
                            # print " |  EstRTT : ", flow_buffer[i][9]
                            client_sent.remove(sent_pkt)
                            server_received.append(sent_pkt)
                            flow_buffer[i][7] += sent_pkt[4] #TODO :CHANGE TO pSize #for getting total size of packets sent after iteration ends
                            flow_buffer[i][6] += 1 #UPDATE NUMBER OF PACKETS RECEIVED BY SERVER
                if (tcp_packet.payloadLength > 0):
                    # SERVER IS SENDING SOME DATA TO CLIENT
                    # print " >> Also contains HTTP Packet - Packet being added to server_sent buffer, with AAN =", str(tcp_packet.seqNum + max(1, tcp_packet.payloadLength))
                    # check if it is retransmission
                    for sent_pkt in server_sent:
                        if(sent_pkt[0] == flow[0] and sent_pkt[2] == tcp_packet.seqNum + max(1, tcp_packet.payloadLength)):
                            #this is a retransmission
                            retransmissions[flow[0]] += 1

                    server_sent.append([flow[0], cnt, tcp_packet.seqNum + max(1, tcp_packet.payloadLength), tcp_packet.timestamp, tcp_packet.pSize, tcp_packet.seqNum, http_packet, tcp_packet.ackNum])
                flow_buffer[i][4] += 1 #numPKTSSentByServer
            else:
                raise Exception("Invalid Direction !")
            return True #flow_buffer[i][3] + flow_buffer[i][4]
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
        if(((0b00000100 & b2) >> 2) == 0):
            self.others = tcp_packet[24:]
            self.MSSKind = int(hex(tcp_packet[20]), base=16)
            self.MSSLength = int(hex(tcp_packet[21]), base=16)
            self.MSSValue = decimalize(tcp_packet[22:24])
        else:
            self.others = None
            self.MSSKind = None
            self.MSSLength = None
            self.MSSValue = None
        self.pSize = len(tcp_packet)
        self.payloadLength = len(tcp_packet) - dataoffset
        self.totalFrameSize = tfs


    def get_flags(self):
        """
        Helper function to return the flags value in boolean 0/1 values.
        :return: a list of 8 flags, each of boolean type
        """
        return [self._CWR, self._ECE, self._URG, self._ACK, self._PSH, self._RST, self._SYN, self._FIN]


class HTTPPacket:
    """
        This is the class that defines a TCPPacket object
        """
    def __init__(self, http_packet):
        http_data = str(http_packet).split("\r\n")
        del http_data[-1]
        self.http_headers = http_data
        self.http_data = http_packet
        # self.http_data = http_packet.decode("utf-8").split("\r\n")



class MQTTPacket:
    """
    This is the class that defines an MQTTPacket Object
    """
    def __init(self, mqtt_packet):
        mqtt_data =  str(mqtt_packet).split("\r\n")
        # del http_data[-1]
        self.http_headers = mqtt_data
        self.http_data = mqtt_packet

def parse_packet(pkt, ts):
    """
    The function takes a raw packet, and extracts the TCP Packet out of it. (Discards the Ethernet and IP headers)
    :param pkt: The raw packet with ethernet and IP headers
    :param ts: Timestamp of teh packet
    :return: A TCPPacket class object, TCP Packet
    """
    global numFlows, flow_buffer, client_sent, server_received, server_sent, client_received, retransmissions, end_ts
    eth_packet = bytearray(pkt)
    tcp_packet = TCPPacket(eth_packet[24:], ts, len(pkt))
    if(tcp_packet.payloadLength > 0):
        http_packet = HTTPPacket(eth_packet[(24+tcp_packet.dataOff):])
        return [tcp_packet, http_packet]
    else:
        return [tcp_packet, False]


def capture_flow(pkt_hist):
    """
    Monitors the flow in the file.
    :param pkt_hist: a list of raw eth packets
    :return: 0 (No errors)
    """
    closedby = []
    global numFlows, flow_buffer, client_sent, server_received, server_sent, client_received, retransmissions, end_ts, last_push_ts
    print "Starting capture"
    cnt = 0
    for ts, pkt in pkt_hist:
        cnt+=1
        # print "PACKET -----" + str(cnt)
        tcp_packet, http_packet = parse_packet(pkt, ts)

        # print "Seq Num :", str(tcp_packet.seqNum), "| Ack Num :", tcp_packet.ackNum, "| Packet Size :", tcp_packet.pSize, "| Payload Length :", tcp_packet.payloadLength, "| HTTP :", http_packet
        if(tcp_packet._PSH == 1):
            last_push_ts = ts

        fState = getFlowStateForPacket(tcp_packet)
        # print "fState = ", fState
        if(fState == 2):
            #This means that the flow is in active state
            # print "Packet belongs to Flow", str(getFlowID(tcp_packet)), "which is already in ACTIVE state."
            pkt_id = add_packet(tcp_packet, http_packet, cnt, ts)
            if (tcp_packet._FIN == 1 and getTransDirection(tcp_packet) == 0):
                updateFlowState(tcp_packet, 3)
                closedby.append([getFlowID(tcp_packet), cnt, "SENDERCLOSE"])
                # FIN ACKed by sender
            if(tcp_packet._FIN == 1 and getTransDirection(tcp_packet) == 1):
                updateFlowState(tcp_packet, 4)
                closedby.append([getFlowID(tcp_packet), cnt, "RECVRCLOSE"])
                # FIN ACKed by server
        elif(fState == 3):
            pkt_id = add_packet(tcp_packet, http_packet, cnt, ts)
            if (tcp_packet._FIN == 1 and getTransDirection(tcp_packet) == 1):
                updateFlowState(tcp_packet, 5)
                closedby.append([getFlowID(tcp_packet), cnt, "RECVRCLOSE"])
                end_ts[getFlowID(tcp_packet)] = ts
                # Was in 3 state (finned by sender). Now also FIN ACKed by server
        elif(fState == 4):
            pkt_id = add_packet(tcp_packet, http_packet, cnt, ts)
            if (tcp_packet._FIN == 1 and getTransDirection(tcp_packet) == 0):
                updateFlowState(tcp_packet, 5)
                closedby.append([getFlowID(tcp_packet), cnt, "SENDERCLOSE"])
                end_ts[getFlowID(tcp_packet)] = ts
                # Was in 4 state (finned by server). Now also FIN ACKed by sender
        elif(fState == 5):
            if(tcp_packet._ACK == 1):
                # Just a stupid ack
                add_packet(tcp_packet, http_packet, cnt, ts)
            elif(tcp_packet._RST == 1):
                # print ">> RST Packet"
                pass
            else:
                # print "Suspicious Packet."
                # print(closedby)
                # printFlowBuffer()
                break
        else:
            if(tcp_packet._RST == 1):
                print "RST Packet"
                updateFlowState(tcp_packet, 5)
                end_ts[getFlowID(tcp_packet)] = ts
            if(tcp_packet._SYN == 1 and tcp_packet._ACK == 0):
                print "Flow initiated with timestamp", ts
                fid = newFlow(tcp_packet)
                # updateFlowState(fid, 0) NO NEED TO DO THAT, WHEN WE CREATE A NEW FLOW, ITS DEFAULT STATE IS 0
            if(tcp_packet._SYN == 1 and tcp_packet._ACK == 1):
                print "Flow SYN/ACK Received"
                updateFlowState(tcp_packet, 1)
            if(tcp_packet._SYN == 0 and tcp_packet._ACK == 1):
                updateFlowState(tcp_packet, 2)
                updateFlowTS(tcp_packet, ts)
            pkt_id = add_packet(tcp_packet, http_packet, cnt, ts)
        # print "Sent Buffer Length : ", len(client_sent), " | Received Buffer Length : ", len(server_sent), " | Acked Buffer Length : ", len(server_received)
        # printFlowBuffer()
        # print "\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"
        if(pkt_id == False):
            print " >> Add Packet Failure"
            break
    # print closedby
    return 0




detectList = []
print "\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"
print "ANALYSING MQTT pcap"
pkt_hist = pcap.pcap('mqtt_start.pcap')
capture_flow(pkt_hist)
# print "--------------------------------------------------"
printFlowBuffer()
# print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
client_received.sort(key=lambda x: (x[0], x[5]))
server_received.sort(key=lambda x: (fetchFlowDetails(x[0])[3], x[5]))
totalByteSize = 0
totalSent = 0
start_ts = {}
for flow in flow_buffer:
    start_ts[flow[0]] = flow[1].start_timestamp


for flow in flow_buffer:
    totalByteSize = totalByteSize + flow[7] + flow[8]
for flow in flow_buffer:
    totalSent = totalSent + flow[3] + flow[4]
print "Average Bytes Per Flow : ", str(totalByteSize/numFlows)
print "Total Byte Size : ", str(totalByteSize)
print "Total Number of Packets Sent : ", str(totalSent)
detectList.append(totalByteSize/numFlows)



reset_all_vars()


detectList = []
print "\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"
print "ANALYSING HTTP pcap"
pkt_hist = pcap.pcap('http_start.pcap')
capture_flow(pkt_hist)
# print "--------------------------------------------------"
printFlowBuffer()
# print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
client_received.sort(key=lambda x: (x[0], x[5]))
server_received.sort(key=lambda x: (fetchFlowDetails(x[0])[3], x[5]))
totalByteSize = 0
totalSent = 0
start_ts = {}
for flow in flow_buffer:
    start_ts[flow[0]] = flow[1].start_timestamp


for flow in flow_buffer:
    totalByteSize = totalByteSize + flow[7] + flow[8]
for flow in flow_buffer:
    totalSent = totalSent + flow[3] + flow[4]
print "Average Bytes Per Flow : ", str(totalByteSize/numFlows)
print "Total Byte Size : ", str(totalByteSize)
print "Total Number of Packets Sent : ", str(totalSent)
detectList.append(totalByteSize/numFlows)