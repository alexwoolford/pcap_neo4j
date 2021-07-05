package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
)

func main() {

	var neo4jUrl string
	var database string
	var neo4jUser string
	var neo4jPass string
	var pcapFile string
	flag.StringVar(&neo4jUrl, "url", "localhost", "Neo4j URL")
	flag.StringVar(&database, "database", "neo4j", "Neo4j database")
	flag.StringVar(&neo4jUser, "user", "neo4j", "Neo4j user")
	flag.StringVar(&neo4jPass, "password", "", "Neo4j password")
	flag.StringVar(&pcapFile, "file", "", "PCAP file")
	flag.Parse()

	driver, driverError := neo4j.NewDriver(neo4jUrl, neo4j.BasicAuth(neo4jUser, neo4jPass, ""))
	if driverError != nil {
		//return "", err
		panic(fmt.Errorf("Fatal driver error Neo4j client: %w \n", driverError))
	}
	defer driver.Close()

	if handle, err := pcap.OpenOffline(pcapFile); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {

			if packet.NetworkLayer() != nil {

				srcIP := packet.NetworkLayer().NetworkFlow().Src()
				dstIP := packet.NetworkLayer().NetworkFlow().Dst()
				unixTime := packet.Metadata().Timestamp.UnixNano()

				srcDstTimestamp := fmt.Sprintf("src: %s, dst: %s, timestamp: %d", srcIP, dstIP, unixTime)

				fmt.Println(srcDstTimestamp)

				srcDstError := addSrcDstConnection(driver, database, srcIP, dstIP, unixTime)
				if srcDstError != nil {
					panic(fmt.Errorf("Fatal driver error Neo4j client: %w \n", srcDstError))
				}

			}
		}
	}

}

func addSrcDstConnection(driver neo4j.Driver, database string, srcIP gopacket.Endpoint, dstIP gopacket.Endpoint, unixTime int64) error {

	session := driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite, DatabaseName: database})
	defer session.Close()

	_, err := session.WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
		_, err := tx.Run("MERGE (src:IP {addr: $src}) MERGE (dst:IP {addr: $dst}) MERGE (src)-[:CONNECTED_TO {timestamp: $timestamp}]->(dst)", map[string]interface{}{"src": srcIP.String(), "dst": dstIP.String(), "timestamp": unixTime})
		return err, nil
	})

	return err
}
