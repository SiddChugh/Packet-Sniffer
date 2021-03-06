# Packet Sniffer
Packet sniffer implemented in Python3 that allows users to monitor traffic runnning through the local network.
After every 10 seconds, the application outputs the counts of each packet transmitted between the two unique sources in the session are printed to the stdout. When the user decides to close the session, the summary that includes information such as the total number of packets transmitted during the session and a list of all the packets exchanged between two unique sources are also printed.

# Usage
`sudo python3 sniffer.py interface`
Press `Ctrl + C` to stop the application.

# Format of Output
## *Format of packets captured:*
Source IP: <br>
Destination IP: <br>
IP Protocol used: <br>
` If protocol is TCP or UDP` <br>
&nbsp;&nbsp; Source Port Number: <br>
&nbsp;&nbsp; Destination Port Number <br>

## *Format of counts of each packet transmitted between the two unique sources:*
`Source IP <---> Destination IP : Protocol, Number of packets exchanged`
# References
- [Raw sockets Tutorial](https://www.opensourceforu.com/2015/03/a-guide-to-using-raw-sockets/)
- [Python3 Sockets Reference](https://docs.python.org/3/library/socket.html)
- [Python3 Structs Reference](https://docs.python.org/3/library/struct.html)
- [List of IP protocols](https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers)
- [EtherType](https://en.wikipedia.org/wiki/EtherType)
- [Linux Types Reference](https://chromium.googlesource.com/native_client/linux-headers-for-nacl/+/2dc04f8190a54defc0d59e693fa6cff3e8a916a9/include/linux/types.h)