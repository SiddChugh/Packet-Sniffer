# Packet Sniffer
Packet sniffer implemented in Python3 that allows users to monitor traffic runnning through the local network.
The application outputs source / destination IP address and protocol for each packet transmitted through the provided interface. If the IP protocol for the packet turns out to be either UDP or TCP, then the source / destination port numbers are outputted as well. 
Additionally, after every 10 seconds, the counts of each packet transmitted between the two unique sources in the session are printed to the stdout. When the user decides to close the session, the summary that includes information such as the total number of packets transmitted during the session and a list of all the packets exchanged between two unique sources are also printed.

# Usage
`sudo python3 sniffer.py interface`
Press `Ctrl + C` to stop the application.

# References
- [Raw sockets Tutorial](https://www.opensourceforu.com/2015/03/a-guide-to-using-raw-sockets/)
- [Python3 Sockets Reference](https://docs.python.org/3/library/socket.html)
- [Python3 Structs Reference](https://docs.python.org/3/library/struct.html)
- [List of IP protocols](https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers)
- [EtherType](https://en.wikipedia.org/wiki/EtherType)
- [Linux Types Reference](https://chromium.googlesource.com/native_client/linux-headers-for-nacl/+/2dc04f8190a54defc0d59e693fa6cff3e8a916a9/include/linux/types.h)