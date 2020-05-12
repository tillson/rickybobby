package parser

import (
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var dnsSchemaPool = sync.Pool{
	New: func() interface{} { return new(DnsSchema) },
}

var packetPool = sync.Pool{
	New: func() interface{} {
		packet := LayeredPacket{}
		packet.parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
			&packet.ethernet, &packet.ip4, &packet.ip6, &packet.tcp, &packet.udp, &packet.dot1q)
		packet.parser.IgnoreUnsupported = true
		return &packet
	},
}
