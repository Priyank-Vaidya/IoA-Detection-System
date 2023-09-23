package main

import (
    // ... Import statements ...
	"fmt"
	"log"
	"time"
	"math"
	"os"
	"encoding/csv"

    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
)

func main() {
    // Define the network interface to capture packets from
    interfaceName := "wlp0s20f3"

    // Open the network interface for packet capture
    handle, err := pcap.OpenLive(interfaceName, 65536, true, pcap.BlockForever)
    if err != nil {
        log.Fatalf("Error opening interface %s: %v", interfaceName, err)
    }
    defer handle.Close()

	// Create a CSV file for output
	csvFile, err := os.Create("packet_output.csv")
	if err != nil {
		log.Fatalf("Error creating CSV file: %v", err)
	}
	defer csvFile.Close()

	
	csvWriter := csv.NewWriter(csvFile)
	defer csvWriter.Flush()

	
	header := []string{
		"Source IP",
		"Destination IP",
		"Packet Count",
		"Protocol",
		"Bytes In",
		"Bytes Out",
		"Entropy (bits/byte)",
		"Total Entropy",
		"Start Time",
	}
	csvWriter.Write(header)

    
	packetCounts := make(map[string]int)
    flowStartTimes := make(map[string]time.Time)
    flowBytesIn := make(map[string]int)
    flowBytesOut := make(map[string]int)
    flowEntropies := make(map[string]float64)
    flowTotalEntropies := make(map[string]float64)

    // Capture packets for 30 seconds
    duration := 30 * time.Second
    endTime := time.Now().Add(duration)

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        // Check if the capture duration has elapsed
        if time.Now().After(endTime) {
            break
        }

        // Extract relevant packet information
        networkLayer := packet.NetworkLayer()
        transportLayer := packet.TransportLayer()
        applicationLayer := packet.ApplicationLayer()

		count := 0

        if networkLayer != nil && transportLayer != nil {
            srcIP := networkLayer.NetworkFlow().Src().String()
            dstIP := networkLayer.NetworkFlow().Dst().String()
            protocol := transportLayer.LayerType().String()

            
            flowKey := fmt.Sprintf("%s -> %s", srcIP, dstIP)

            // Ensure that flow data maps are initialized before use
            if _, exists := packetCounts[flowKey]; !exists {
                flowStartTimes[flowKey] = time.Now()
                flowBytesIn[flowKey] = 0
                flowBytesOut[flowKey] = 0
                flowEntropies[flowKey] = 0.0
                flowTotalEntropies[flowKey] = 0.0
            }

            // Update packet count for the flow
			if applicationLayer != nil {
				// Update packet count for the flow
				packetCounts[flowKey]++
	
				// Update bytes in and bytes out for the flow
				packetLength := len(packet.Data())
				if srcIP == networkLayer.NetworkFlow().Src().String() {
					flowBytesOut[flowKey] += packetLength
				} else {
					flowBytesIn[flowKey] += packetLength
				}
	
				
				data := applicationLayer.Payload()
				entropy := calculateEntropy(data)
				flowEntropies[flowKey] = entropy
			


			row := []string{
				srcIP,
				dstIP,
				fmt.Sprintf("%d", packetCounts[flowKey]),
				protocol,
				fmt.Sprintf("%d", flowBytesIn[flowKey]),
				fmt.Sprintf("%d", flowBytesOut[flowKey]),
				fmt.Sprintf("%.2f", flowEntropies[flowKey]),
				fmt.Sprintf("%.2f", flowTotalEntropies[flowKey]),
				flowStartTimes[flowKey].Format("2006-01-02 15:04:05"),
			}
			csvWriter.Write(row)
			count++
			

            // Print flow details
            // fmt.Printf("Source IP: %s, Destination IP: %s, "+
            //     "Packet Count: %d, Protocol: %s, "+
            //     "Bytes In: %d, Bytes Out: %d, "+
            //     "Entropy (bits/byte): %.2f, Total Entropy: %.2f, "+
            //     "Start Time: %s\n",
            //     srcIP, dstIP, packetCounts[flowKey], protocol,
            //     flowBytesIn[flowKey], flowBytesOut[flowKey],
            //     entropy, flowTotalEntropies[flowKey],
            //     flowStartTimes[flowKey].Format("2006-01-02 15:04:05"))
        }
		csvWriter.Flush()
		print(count)
	}
    }
}

func calculateEntropy(data []byte) float64 {
    if len(data) == 0 {
        return 0.0
    }

    // Calculate entropy using Shannon's entropy formula
    frequency := make(map[byte]float64)
    for _, b := range data {
        frequency[b]++
    }

    entropy := 0.0
    totalBytes := float64(len(data))
    for _, count := range frequency {
        probability := count / totalBytes
        entropy -= probability * math.Log2(probability)
    }

    return entropy
}
