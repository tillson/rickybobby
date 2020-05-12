package parser

import "sync"

var dnsSchemaPool = sync.Pool{
	New: func() interface{} { return new(DnsSchema) },
}
