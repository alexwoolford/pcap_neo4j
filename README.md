# pcap_neo4j

It's very natural to model network traffic in a graph since a network _is_ a graph. We can model network traffic where each IP address is a node, and a connection is a relationship.

Network engineers will often capture packets in a `pcap` file that can be analyzed by a tool such as [Wireshark](https://www.wireshark.org/).

This is a command-line utility that parses a packet capture file into a graph. Here's an example:

    go run pcap_neo4j.go -file sample.pcap -url bolt://neo4j.woolford.io:7687 -database pcap -user neo4j -password s3cret123

