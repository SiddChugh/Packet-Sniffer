import socket
import sys
import struct
import threading
import time
import datetime
import asyncio

# Dictionary to track number of packets exchanged between two unique sources
track_packets_bw_sources = dict()

# Total Number of packets captured in the session
NUM_PACKETS = 0


#------------------------------------------------------------------------------
# ----------------------C Struct Specific Constants---------------------------
#------------------------------------------------------------------------------

# Ethernet mac address variable size 
ETHER_MAC_ADDRESS_VARIABLE_SIZE = 6 # equivalent to unsigned char[6]

# IPv4 Version Member variable size
IPv4_TOS_VARIABLE_SIZE          = 1 # equivalent to unsigned uint8_t

# IPv4 Total Length Member variable size
IPv4_TOT_LEN_VARIABLE_SIZE      = 2 # equivalent to uint16_t

# IPv4 ID Member variable size
IPv4_ID_VARIABLE_SIZE           = 2 # equivalent to unsigned uint16_t

# IPv4 Fragment Offset Member variable size
IPv4_FRAG_OFF_VARIABLE_SIZE     = 2 # equivalent to unsigned uint16_t

# IPv4 Time to Live Member variable size
IPv4_TTL_VARIABLE_SIZE          = 1 # equivalent to unsigned uint8_t

# IPv4 Checksum Member variable size
IPv4_CHECK_VARIABLE_SIZE        = 2 # equivalent to unsigned uint16_t

#------------------------------------------------------------------------------
#----------------------Protocol Specific Constants-----------------------------
#------------------------------------------------------------------------------

# Constant that indicates presence of IPv4 Protocol in Ethernet Frame
ETHER_FRAME_IPV4 = 0x0800   

# Constant that indicates presence of TCP Protocol in the datagram
TCP_DATAGRAM     = 0x06

# Constant that indicates presence of UDP Protocol in the datagram
UDP_DATAGRAM     = 0x11

# Helper function to print the counts of each packet transmitted between 
# the two unique sources
async def printSessionInformation():
  period = 10 

  if (len (track_packets_bw_sources) > 0):
    print ("Summary of the number of packets exchanged between two unique " \
          + "sources at " + time.ctime() + "\n")
    print ("Format: Source IP <---> Destination IP : Number of packets " \
          + "exchanged")

    # List the number of packets exchanged between pairs of unique source and
    # destination IP addresses.
    for key in track_packets_bw_sources:
      cleansed_key = key[:key.rfind(".")]
      print (cleansed_key, ":", track_packets_bw_sources[key])

    print ("\n")
    print ("Total Number of packets captured in the session as of " + \
          time.ctime() + " are " + str (NUM_PACKETS) + "\n")
  else:
    print ("No packets were captured in the session as of " + time.ctime() \
          + "\n")

  #time.sleep (period)


# Print number of packets exchanged between two unique source
# after every 10 seconds
def printSessionInformationPeriodically(): 
  period = 10 

  while True:
    printSessionInformation()

    # Pause the thread for 10 seconds
    time.sleep (period)

# Start Sniffing Packets
async def main():
  global track_packets_bw_sources
  global NUM_PACKETS

  print ("-------------Start Sniffing packets.-------------------------------")
  print ("After every 10 seconds, counts of each packet transmitted between " \
        "two unique sources are printed\n")
  print ("Press Ctrl + C to stop the process and display the " + \
  "statistics between two unique sources.\n") 

  # socket.AF_PACKET, socket.SOCK_RAW indicates the socket family and type
  # required to implement a raw socket.
  # socket.ntohs(0x0003) allows this program to capture all the packets
  conn = socket.socket (socket.PF_PACKET, socket.SOCK_RAW, \
                        socket.ntohs (0x0003))
  
  # # Spawn a background thread thart would print number of packets exchanged
  # # between two unique sources after every 10 seconds
  # periodic_task = threading.Thread (target = \
  #                                   printSessionInformationPeriodically)
  # # Make sure that thread ends when the main thread is closed
  # periodic_task.daemon = True
  # # Start and stop the thread
  # periodic_task.start()
  currentTime = datetime.datetime.utcnow()
  try:
    while True:
      if ((datetime.datetime.utcnow() - currentTime).total_seconds() > 10):
        await asyncio.gather(printSessionInformation())
        currentTime = datetime.datetime.utcnow()
        
      # Bind the socket to the interface requested by the user
      try:
        conn.bind ((sys.argv[1], 0))
      except OSError:
        print ("Interface not available")
        sys.exit (1)

      

      # 65536 bytes: The maximum theoretical datagram size
      ethernet_frame, address = conn.recvfrom (65535)
            
      # eternet_frame_data is a sequence of bytes which is equivalent to 
      # struct ethhdr listed in if_ether.h header
      # The first two variables contained in the struct are source and 
      # destination mac addresses that are of char arrays of size 6 bytes 
      # each. The third variable is EtherType which indicates the protocol of 
      # the frame and it is of type short int which is of size 2 bytes.
      # Since we want to capture only IPv4 packets, we can filter that by 
      # looking at the EtherType field, we can retrive that by accessing the 
      # bytes encapsulated between the indices 12 and 14. 
      ether_type_start_index = ETHER_MAC_ADDRESS_VARIABLE_SIZE + \
                               ETHER_MAC_ADDRESS_VARIABLE_SIZE
      ether_type_size        = struct.calcsize ('H')
      ether_type_end_index   = ether_type_start_index + ether_type_size
      etherType              = struct.unpack ('H', \
                               ethernet_frame[ether_type_start_index : \
                               ether_type_end_index])[0]

      # Proceed only if the captured frame contains IPv4 packets
      if (socket.htons (etherType) == ETHER_FRAME_IPV4):
        packet = ethernet_frame[ether_type_end_index :]

        # data after the index 14 in the frame contains information about the 
        # IP layer. The IP layers provides us various pieces of information 
        # such as source and destination IP addresses and transport layer 
        # protocol. The structure of the IP Header is defined in struct iphdr 
        # which can be found in ip.h file. Since we are only interested in the 
        # transport layer protocol used and the source / destination IP 
        # addresses. Therefore,  we can skip over the other fields defined in 
        # the struct.
        transport_layer_protocol_start_index = IPv4_TOS_VARIABLE_SIZE + \
                                               IPv4_TOT_LEN_VARIABLE_SIZE + \
                                               IPv4_ID_VARIABLE_SIZE + \
                                               IPv4_FRAG_OFF_VARIABLE_SIZE + \
                                               IPv4_TTL_VARIABLE_SIZE + 1
        transport_layer_protocol_end_index  = \
        transport_layer_protocol_start_index + \
        struct.calcsize ('! B')
        transport_layer_protocol = struct.unpack ('! B', \
                                    packet[ \
                                    transport_layer_protocol_start_index: \
                                    transport_layer_protocol_end_index])[0]

        IP_address_start_index = transport_layer_protocol_end_index + \
                                 IPv4_CHECK_VARIABLE_SIZE
        IP_address_end_index   = IP_address_start_index + \
                               struct.calcsize ('! 4s 4s')

        IP_source_address, IP_dest_address = struct.unpack ('! 4s 4s', \
                                             packet[IP_address_start_index: \
                                                    IP_address_end_index] )
        IP_source_address = '.'.join (map (str,IP_source_address))
        IP_dest_address   = '.'.join (map (str,IP_dest_address))
        
        dict_key = IP_source_address + " <--> " + IP_dest_address + "." + \
                   str(transport_layer_protocol)
          
        print ("--------------Packet Information Start-----------------------")
        print ("IP Source Address: " + IP_source_address)
        print ("IP Destination Address: " + IP_dest_address)
        print ("IP Protocol used: " + str (transport_layer_protocol))
        
        segment = packet[IP_address_end_index:]

        if (transport_layer_protocol == TCP_DATAGRAM or \
            transport_layer_protocol == UDP_DATAGRAM):
          protocol = "TCP" if transport_layer_protocol == TCP_DATAGRAM \
                      else "UDP"
          print ("The protocol used in this transmission is " + protocol)

          # The TCP / UDP header information is encapsulated in struct tcphdr 
          # and udphdr respectively. The struct information can be foundin the 
          # files tcp.h and udp.h.    
          # The first two member variables of this struct are source and 
          # destination port numbers.
          src_port, dest_port = struct.unpack ('! H H', \
                                segment[:struct.calcsize ('! H H')] )

          # Dictionary key is updated to include port numbers if the protocol
          # is either TCP or UDP
          dict_key = IP_source_address + ":" +  str(src_port) + " <--> " + \
                     IP_dest_address + ":" + str(dest_port) + "." + \
                     str(transport_layer_protocol)

          print ("Source port " + str (src_port))
          print ("Destination port " + str (dest_port))
          print ("Captured at " + time.ctime())
        
        # Unique pair of sources
        if (not(dict_key in track_packets_bw_sources)):
          track_packets_bw_sources[dict_key] = {"protocol" : 
                                                transport_layer_protocol, 
                                                "num_packets" : 1}
        # Increment the number of packets exchanged between the sources
        else :
          number_of_packets_exchanged = track_packets_bw_sources[dict_key] \
                                                                ["num_packets"]
          track_packets_bw_sources[dict_key]["num_packets"] = \
          number_of_packets_exchanged + 1

        # Increment number of packets exchanged in the session.     
        NUM_PACKETS += 1

        print ("---------------Packet Information End----------------------\n")

  # Display stastics when the user presses Ctrl + C
  except KeyboardInterrupt:
    print ("--------------End of Session Statistics------------------------\n")
    
    print ("Total Number of packets captured in the session " + \
    str (NUM_PACKETS) + "\n")

    printSessionInformation()
    
    print ("Exiting....")

if __name__=="__main__":
  loop = asyncio.get_event_loop()
  loop.run_until_complete(main())
