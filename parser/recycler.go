package parser

import "sync"

var dnsSchemaPool = sync.Pool{
	New: func() interface{} { return new(DnsSchema) },
}

var avroSchemaPool = sync.Pool{
	New: func() interface{} { return new(AvroDnsSchema) },
}
