package parser

import (
	"crypto/sha256"
	"fmt"
	"io"
	_ "net/http/pprof"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

const (
	DnsAnswer     = iota
	DnsAuthority  = iota
	DnsAdditional = iota
)

var (
	DoParseTcp          = true
	DoParseQuestions    = false
	DoParseQuestionsEcs = true
	Source              = ""
	Sensor              = ""
	Config              = ""
)

func ParseFile(fname string) {
	var (
		handle *pcap.Handle
		err    error
	)

	if "-" == fname {
		handle, err = pcap.OpenOfflineFile(os.Stdin)
	} else {
		handle, err = pcap.OpenOffline(fname)
	}

	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	ParseDns(handle)
}

func ParseDevice(device string, snapshotLen int32, promiscuous bool, timeout time.Duration) {
	handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Setup BPF filter on handle
	bpfFilter := "udp port 53"
	if DoParseTcp {
		bpfFilter = "port 53"
	}
	err = handle.SetBPFFilter(bpfFilter)
	if err != nil {
		log.Warnf("Could not set BPF filter: %v\n", err)
	}

	ParseDns(handle)
}

var (
	ip4 *layers.IPv4
	ip6 *layers.IPv6
	tcp *layers.TCP
	udp *layers.UDP
)

type LayeredPacket struct {
	ethernet layers.Ethernet
	ip4      layers.IPv4
	ip6      layers.IPv6
	tcp      layers.TCP
	udp      layers.UDP
	dot1q    layers.Dot1Q
	parser   *gopacket.DecodingLayerParser
}

func ParseDns(handle *pcap.Handle) {

	var (
		stats Statistics
	)

	// Set the source and sensor for packet source

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true

	for {
		packet := packetPool.Get().(*LayeredPacket)
		// packet, err := packetSource.NextPacket
		decodedLayers := make([]gopacket.LayerType, 0, 10)
		bytes, info, err := handle.ZeroCopyReadPacketData()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Warnf("Error:", err)
			continue
		}
		err = packet.parser.DecodeLayers(bytes, &decodedLayers)
		if err != nil {
			log.Warnf("Error:", err)
			continue
		}
		schema := dnsSchemaPool.Get().(*DnsSchema)
		schema.Sensor = Sensor
		schema.Source = Source
		stats.PacketTotal++

		AnalyzePacket(decodedLayers, packet, schema, &info, &stats)
	}

	// analyzeChannel := make(chan *gopacket.Packet, 500000)
	// for i := 0; i < 1500000; i++ {
	// 	go func() {
	// 		for packet := range analyzeChannel {
	// 			schema := dnsSchemaPool.Get().(*DnsSchema)
	// 			schema.Sensor = Sensor
	// 			schema.Source = Source
	// 			stats.PacketTotal++
	// 			go AnalyzePacket(*packet, schema, &stats, done)
	// 			<-done
	// 		}
	// 	}()
	// }
	// for {
	// 	packet, err := packetSource.NextPacket()
	// 	if err == io.EOF {
	// 		break
	// 	} else if err != nil {
	// 		log.Println("Error:", err)
	// 		continue
	// 	}
	// 	schema := dnsSchemaPool.Get().(*DnsSchema)
	// 	schema.Sensor = Sensor
	// 	schema.Source = Source
	// 	stats.PacketTotal++
	// 	AnalyzePacket(packet, schema, &stats)
	// }

	// done := make(chan bool, 500000)
	// for packet := range packetSource.Packets() {
	// 	schema := dnsSchemaPool.Get().(*DnsSchema)
	// 	schema.Sensor = Sensor
	// 	schema.Source = Source
	// 	stats.PacketTotal++
	// 	AnalyzePacket(packet, schema, &stats)
	// }

	log.Infof("Number of TOTAL packets: %v", stats.PacketTotal)
	log.Infof("Number of IPv4 packets: %v", stats.PacketIPv4)
	log.Infof("Number of IPv6 packets: %v", stats.PacketIPv6)
	log.Infof("Number of UDP packets: %v", stats.PacketUdp)
	log.Infof("Number of TCP packets: %v", stats.PacketTcp)
	log.Infof("Number of DNS packets: %v", stats.PacketDns)
	log.Infof("Number of FAILED packets: %v", stats.PacketErrors)
}

func AnalyzePacket(decodedLayers []gopacket.LayerType, packet *LayeredPacket, schema *DnsSchema, info *gopacket.CaptureInfo, stats *Statistics) {

	// Let's analyze decoded layers
	var msg *dns.Msg

	for _, curLayer := range decodedLayers {
		switch curLayer {
		case layers.LayerTypeIPv4:
			schema.SourceAddress = packet.ip4.SrcIP.String()
			schema.DestinationAddress = packet.ip4.DstIP.String()
			schema.Ipv4 = true
			stats.PacketIPv4++
		case layers.LayerTypeIPv6:
			schema.SourceAddress = packet.ip6.SrcIP.String()
			schema.DestinationAddress = packet.ip6.DstIP.String()
			schema.Ipv4 = false
			stats.PacketIPv6++
		case layers.LayerTypeTCP:
			stats.PacketTcp++

			if !DoParseTcp {
				// done <- false
				return
			}

			msg = new(dns.Msg)
			if err := msg.Unpack(packet.tcp.Payload); err != nil {
				log.Errorf("Could not decode DNS: %v\n", err)
				stats.PacketErrors++
				// done <- false
				return
			}
			stats.PacketDns++

			schema.SourcePort = int(packet.tcp.SrcPort)
			schema.DestinationPort = int(packet.tcp.DstPort)
			schema.Udp = false
			schema.Sha256 = fmt.Sprintf("%x", sha256.Sum256(tcp.Payload))
		case layers.LayerTypeUDP:
			stats.PacketUdp++

			msg = new(dns.Msg)
			if err := msg.Unpack(packet.udp.Payload); err != nil {
				log.Errorf("Could not decode DNS: %v\n", err)
				stats.PacketErrors++
				// done <- false
				return
			}
			stats.PacketDns++

			schema.SourcePort = int(packet.udp.SrcPort)
			schema.DestinationPort = int(packet.udp.DstPort)
			schema.Udp = true
			schema.Sha256 = fmt.Sprintf("%x", sha256.Sum256(packet.udp.Payload))
		}
	}

	packetPool.Put(packet)

	// This means we did not attempt to parse a DNS payload
	if msg == nil {
		log.Debugf("Error decoding some part of the packet")
		return
		// // Let's check if we had any errors decoding any of the packet layers
		// if err := packet.ErrorLayer(); err != nil {
		// 	stats.PacketErrors++
		// }
		// // done <- false
		// return
	}

	// Ignore questions unless flag set
	if !msg.Response && !DoParseQuestions && !DoParseQuestionsEcs {
		// done <- false
		return
	}

	// Fill out information from DNS headers
	schema.Timestamp = info.Timestamp.Unix()
	schema.Id = int(msg.Id)
	schema.Rcode = msg.Rcode
	schema.Truncated = msg.Truncated
	schema.Response = msg.Response
	schema.RecursionDesired = msg.RecursionDesired

	// Parse ECS information
	schema.EcsClient = nil
	schema.EcsSource = nil
	schema.EcsScope = nil
	if opt := msg.IsEdns0(); opt != nil {
		for _, s := range opt.Option {
			switch o := s.(type) {
			case *dns.EDNS0_SUBNET:
				ecsClient := o.Address.String()
				ecsSource := o.SourceNetmask
				ecsScope := o.SourceScope
				schema.EcsClient = &ecsClient
				schema.EcsSource = &ecsSource
				schema.EcsScope = &ecsScope
			}
		}
	}

	// Reset RR information
	schema.Ttl = nil
	schema.Rname = nil
	schema.Rdata = nil
	schema.Rtype = nil

	// Let's get QUESTION
	// TODO: Throw error if there's more than one question
	for _, qr := range msg.Question {
		schema.Qname = qr.Name
		schema.Qtype = int(qr.Qtype)
	}

	// Let's get QUESTION information on if:
	//   1. Questions flag is set
	//   2. QuestionsEcs flag is set and ECS information in question
	//   3. NXDOMAINs without RRs (i.e., SOA)
	if (DoParseQuestions && !schema.Response) ||
		(DoParseQuestionsEcs && schema.EcsClient != nil && !schema.Response) ||
		(schema.Rcode == 3 && len(msg.Ns) < 1) {
		schema.FormatOutput(nil, -1)
	}

	// Let's get ANSWERS
	for _, rr := range msg.Answer {
		schema.FormatOutput(&rr, DnsAnswer)
	}

	// Let's get AUTHORITATIVE information
	for _, rr := range msg.Ns {
		schema.FormatOutput(&rr, DnsAuthority)
	}

	// Let's get ADDITIONAL information
	for _, rr := range msg.Extra {
		schema.FormatOutput(&rr, DnsAdditional)
	}

	// done <- true

}
