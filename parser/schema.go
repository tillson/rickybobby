package parser

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"rickybobby/producer"
	"strings"
	"sync"

	"github.com/Shopify/sarama"
	"github.com/hamba/avro"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

var (
	Format           = "json"
	OutputType       = ""
	OutputFile       = ""
	OutputStream     *bufio.Writer
	ByteWriteChannel chan []byte
	WriteWaitGroup   *sync.WaitGroup
	WriteDone        chan bool
)

// JSON serialization only supports nullifying types that can accept nil.
// The ECS fields are pointers because they're nullable.
type DnsSchema struct {
	Timestamp          int64   `json:"timestamp"`
	Sha256             string  `json:"sha256"`
	Udp                bool    `json:"udp"`
	Ipv4               bool    `json:"ipv4"`
	SourceAddress      string  `json:"src_address"`
	SourcePort         uint16  `json:"src_port"`
	DestinationAddress string  `json:"dst_address"`
	DestinationPort    uint16  `json:"dst_port"`
	Id                 uint16  `json:"id"`
	Rcode              int     `json:"rcode"`
	Truncated          bool    `json:"truncated"`
	Response           bool    `json:"response"`
	RecursionDesired   bool    `json:"recursion_desired"`
	Answer             bool    `json:"answer"`
	Authority          bool    `json:"authority"`
	Additional         bool    `json:"additional"`
	Qname              string  `json:"qname"`
	Qtype              uint16  `json:"qtype"`
	Ttl                *uint32 `json:"ttl"`
	Rname              *string `json:"rname"`
	Rtype              *uint16 `json:"rtype"`
	Rdata              *string `json:"rdata"`
	EcsClient          *string `json:"ecs_client"`
	EcsSource          *uint8  `json:"ecs_source"`
	EcsScope           *uint8  `json:"ecs_scope"`
	Source             string  `json:"source,omitempty"`
	Sensor             string  `json:"sensor,omitempty"`
}

func (d DnsSchema) FormatOutput(rr *dns.RR, section int) {
	if rr != nil {
		// This works because RR.Header().String() prefixes the RDATA
		// in the RR.String() representation.
		// Reference: https://github.com/miekg/dns/blob/master/types.go
		rdata := strings.TrimPrefix((*rr).String(), (*rr).Header().String())

		// Fill in the rest of the parameters
		// This will not alter the underlying DNS schema
		d.Ttl = &(*rr).Header().Ttl
		d.Rname = &(*rr).Header().Name
		d.Rtype = &(*rr).Header().Rrtype
		d.Rdata = &rdata
		d.Answer = section == DnsAnswer
		d.Authority = section == DnsAuthority
		d.Additional = section == DnsAdditional

		// Ignore OPT records
		if *d.Rtype == 41 {
			return
		}
	}
	go FormatOutputExport(&d)

}

var AvroCodec avro.Schema

func FormatOutputExport(schema *DnsSchema) {
	var schemaIdentifier uint32 = 3
	var schemaIdentifierBuffer []byte = make([]byte, 4)
	binary.BigEndian.PutUint32(schemaIdentifierBuffer, schemaIdentifier)

	if Format == "avro" {
		avroMap := DnsSchemaToAvro(schema)
		WriteWaitGroup.Add(1)
		ByteWriteChannel <- avroMap
	} else if Format == "json" {
		// jsonData, err := json.Marshal(&schema)
		// if err != nil {
		// 	log.Warnf("Error converting to JSON: %v", err)
		// }
		// if OutputType == "stdout" {
		// 	fmt.Printf("%s\n", jsonData)
		// } else if OutputType == "kafka" {
		// 	codec, err := producer.NewAvroCodec()
		// 	if err != nil {
		// 		log.Fatalf("Failed to convert Go map to Avro JSON data: %v", err)
		// 	}
		// 	avroJSON, err := codec.TextualFromNative(nil, DnsSchemaToAvro(schema))
		// 	producer.Producer.Input() <- &sarama.ProducerMessage{
		// 		Topic: producer.Topic,
		// 		Key:   sarama.StringEncoder(producer.MessageKey),
		// 		Value: sarama.ByteEncoder(avroJSON),
		// 	}
		// } else if OutputType == "file" {
		// 	go func() {
		// 		_, err := OutputStream.Write(jsonData)
		// 		if err != nil {
		// 			log.Fatalf("Failed to output JSON to a file: %v", err)
		// 		}
		// 	}()
		// }
	}
	// dnsSchemaPool.Put(schema)
}

func WriteByteOutput() {
	var schemaIdentifier uint32 = 3
	var schemaIdentifierBuffer []byte = make([]byte, 4)
	binary.BigEndian.PutUint32(schemaIdentifierBuffer, schemaIdentifier)
	schemaVersion := producer.SchemaVersion
	var confluentAvroHeader []byte = make([]byte, schemaVersion)
	for bytes := range ByteWriteChannel {
		if OutputType == "kafka" {
			confluentMessage := append(confluentAvroHeader, bytes...)
			producer.Producer.Input() <- &sarama.ProducerMessage{
				Topic: producer.Topic,
				Key:   sarama.StringEncoder(producer.MessageKey),
				Value: sarama.ByteEncoder(confluentMessage),
			}
		} else if OutputType == "stdout" {
			fmt.Printf("%s\n", bytes)
		} else if OutputType == "file" {
			fmt.Fprint(OutputStream, bytes)
			err := OutputStream.Flush()
			if err != nil {
				log.Fatalf("Failed to output avro to a file: %v", err)
			}
			// _, err := OutputStream.Write(bytes)
			// _, err := fmt.Fprintln(OutputmStream, bytes)
		}
		WriteWaitGroup.Done()
	}
}

// ConsumeAvro consumes DNSSchema from WriteChannel, turns it into an avro buffer, and
// writes it to its right place.
func WriteMapOutput() {
	// var schemaIdentifier uint32 = 3
	// var schemaIdentifierBuffer []byte = make([]byte, 4)
	// binary.BigEndian.PutUint32(schemaIdentifierBuffer, schemaIdentifier)
	// if err != nil {
	// 	log.Fatalf("Failed to initialize avro codec: %v", err)
	// }
	// schemaVersion := producer.SchemaVersion
	// var confluentAvroHeader []byte = make([]byte, schemaVersion)

	// for avroMap := range MapWriteChannel {
	// 	if OutputType == "kafka" {
	// 		binary, err := codec.BinaryFromNative(nil, avroMap)
	// 		confluentMessage := append(confluentAvroHeader, binary...)
	// 		if err != nil {
	// 			log.Fatalf("Failed to convert Go map to Avro binary data: %v", err)
	// 		}
	// 		producer.Producer.Input() <- &sarama.ProducerMessage{
	// 			Topic: producer.Topic,
	// 			Key:   sarama.StringEncoder(producer.MessageKey),
	// 			Value: sarama.ByteEncoder(confluentMessage),
	// 		}
	// 	} else if OutputType == "stdout" {
	// 		fmt.Printf("%s\n", avroMap)
	// 	} else if OutputType == "file" {
	// 		var values []map[string]interface{}
	// 		values = append(values, avroMap)
	// 		err = OCFWriter.Append(values)
	// 		if err != nil {
	// 			log.Fatalf("Error writing values to file: %v", err)
	// 		}
	// 		if err != nil {
	// 			log.Fatalf("Failed to output AVRO to a file: %v", err)
	// 		}
	// 	}
	// 	WriteWaitGroup.Done()
	// }
}

type stringUnion struct {
	String string `avro:"string"`
}

// type boolUnion struct {
// 	Bool bool `avro:"boolean"`
// }
type intUnion struct {
	Int int `avro:"int"`
}
type longUnion struct {
	Long int `avro:"long"`
}

type AvroDnsSchema struct {
	Timestamp          int64                  `avro:"timestamp"`
	Udp                bool                   `avro:"udp"`
	IpVersion          int                    `avro:"ip_version"`
	SourceAddress      string                 `avro:"ip_src"`
	DestinationAddress string                 `avro:"ip_dst"`
	DestinationPort    int                    `avro:"dst_port"`
	Id                 int                    `avro:"txid"`
	Rcode              int                    `avro:"rcode"`
	Truncated          bool                   `avro:"truncated"`
	Response           bool                   `avro:"response"`
	RecursionDesired   bool                   `avro:"recursion_desired"`
	Answer             map[string]interface{} `avro:"answer"`
	Authority          map[string]interface{} `avro:"authority"`
	Additional         map[string]interface{} `avro:"additional"`
	Qname              string                 `avro:"qname"`
	Qtype              int                    `avro:"qtype"`
	Ttl                longUnion              `avro:"ttl,omitempty"`
	Rname              stringUnion            `avro:"rname,omitempty"`
	Rtype              intUnion               `avro:"rtype,omitempty"`
	Rdata              stringUnion            `avro:"rdata,omitempty"`
	EcsClient          stringUnion            `avro:"ecs_client,omitempty"`
	EcsSource          stringUnion            `avro:"ecs_source,omitempty"`
	EcsScope           stringUnion            `avro:"ecs_scope,omitempty"`
	Source             string                 `avro:"source"`
	Sensor             stringUnion            `avro:"sensor,omitempty"`
}

func DnsSchemaToAvro(schema *DnsSchema) []byte {
	avroMap := avroSchemaPool.Get().(*AvroDnsSchema)

	avroMap.Timestamp = schema.Timestamp

	avroMap.SourceAddress = schema.SourceAddress
	avroMap.DestinationAddress = schema.DestinationAddress
	avroMap.DestinationPort = int(schema.DestinationPort)
	avroMap.Id = int(schema.Id)
	avroMap.Rcode = schema.Rcode
	avroMap.Qtype = int(schema.Qtype)
	avroMap.Qname = schema.Qname
	avroMap.RecursionDesired = schema.RecursionDesired
	avroMap.Response = schema.Response
	avroMap.Answer = map[string]interface{}{"boolean": schema.Answer}
	avroMap.Authority = map[string]interface{}{"boolean": schema.Authority}
	avroMap.Additional = map[string]interface{}{"boolean": schema.Additional}
	avroMap.Source = schema.Source

	if schema.Rname != nil {
		avroMap.Rname = stringUnion{String: *schema.Rname}
	}
	if schema.Rtype != nil {
		avroMap.Rtype = intUnion{Int: int(*schema.Rtype)}
	}
	if schema.Rdata != nil {
		avroMap.Rdata = stringUnion{String: *schema.Rdata}
	}
	if schema.Ttl != nil {
		avroMap.Ttl = longUnion{Long: int(*schema.Ttl)}
	}
	if schema.EcsClient != nil {
		avroMap.EcsClient = stringUnion{String: *schema.EcsClient}
	}
	if schema.EcsSource != nil {
		avroMap.EcsSource = stringUnion{String: string(*schema.EcsSource)}
	}
	if schema.EcsScope != nil {
		avroMap.EcsScope = stringUnion{String: string(*schema.EcsScope)}
	}
	if schema.Source != "" {
		avroMap.Sensor = stringUnion{String: schema.Sensor}
	}

	if schema.Ipv4 {
		avroMap.IpVersion = 4
	} else {
		avroMap.IpVersion = 6
	}
	bytes, err := avro.Marshal(AvroCodec, avroMap)
	avroSchemaPool.Put(avroMap)
	if err != nil {
		log.Fatal(err)
	}
	return bytes
}
