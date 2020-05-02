package parser

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"rickybobby/producer"
	"strings"
	"sync"

	"github.com/Shopify/sarama"
	"github.com/leboncoin/structs"
	"github.com/linkedin/goavro"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

var (
	Format         = "json"
	OutputType     = ""
	OutputFile     = ""
	OutputStream   *os.File
	OCFWriter      *goavro.OCFWriter
	WriteChannel   chan *DnsSchema
	WriteWaitGroup *sync.WaitGroup
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
	WriteWaitGroup.Add(1)
	FormatOutputExport(&d)

}

func FormatOutputExport(schema *DnsSchema) {
	var schemaIdentifier uint32 = 3
	var schemaIdentifierBuffer []byte = make([]byte, 4)
	binary.BigEndian.PutUint32(schemaIdentifierBuffer, schemaIdentifier)

	WriteWaitGroup.Add(1)
	if Format == "avro" {
		WriteChannel <- schema
		// codec, err := producer.NewAvroCodec()

		// binary, err := codec.BinaryFromNative(nil, DNSToAvroMap(schema))
		// schemaVersion := producer.SchemaVersion
		// var confluentAvroHeader []byte = make([]byte, schemaVersion)
		// confluentMessage := append(confluentAvroHeader, binary...)
		// if err != nil {
		// 	log.Fatalf("Failed to convert Go map to Avro binary data: %v", err)
		// }
		// if err != nil {
		// 	log.Warnf("Error while initializing avro codec: %v", err)
		// }
		// if OutputType == "kafka" {
		// 	producer.Producer.Input() <- &sarama.ProducerMessage{
		// 		Topic: producer.Topic,
		// 		Key:   sarama.StringEncoder(producer.MessageKey),
		// 		Value: sarama.ByteEncoder(confluentMessage),
		// 	}
		// } else if OutputType == "stdout" {
		// 	fmt.Printf("%s\n", confluentMessage)
		// } else if OutputType == "file" {
		// 	go func() {
		// 		var values []map[string]interface{}
		// 		values = append(values, DNSToAvroMap(schema))
		// 		err := OCFWriter.Append(values)
		// 		if err != nil {
		// 			log.Fatalf("Failed to output AVRO to a file: %v", err)
		// 		}
		// 	}()
		// }
	} else if Format == "json" {
		jsonData, err := json.Marshal(&schema)
		if err != nil {
			log.Warnf("Error converting to JSON: %v", err)
		}
		if OutputType == "stdout" {
			fmt.Printf("%s\n", jsonData)
		} else if OutputType == "kafka" {
			codec, err := producer.NewAvroCodec()
			if err != nil {
				log.Fatalf("Failed to convert Go map to Avro JSON data: %v", err)
			}
			avroJSON, err := codec.TextualFromNative(nil, DNSToAvroMap(schema))
			producer.Producer.Input() <- &sarama.ProducerMessage{
				Topic: producer.Topic,
				Key:   sarama.StringEncoder(producer.MessageKey),
				Value: sarama.ByteEncoder(avroJSON),
			}
		} else if OutputType == "file" {
			go func() {
				_, err := OutputStream.Write(jsonData)
				if err != nil {
					log.Fatalf("Failed to output JSON to a file: %v", err)
				}
			}()
		}
	}
}

// ConsumeAvro consumes DNSSchema from WriteChannel, turns it into an avro buffer, and
// writes it to its right place.
func ConsumeAvro() {
	var schemaIdentifier uint32 = 3
	var schemaIdentifierBuffer []byte = make([]byte, 4)
	binary.BigEndian.PutUint32(schemaIdentifierBuffer, schemaIdentifier)
	codec, err := producer.NewAvroCodec()
	if err != nil {
		log.Fatalf("Failed to initialize avro codec: %v", err)
	}
	schemaVersion := producer.SchemaVersion
	var confluentAvroHeader []byte = make([]byte, schemaVersion)

	for schema := range WriteChannel {
		avroMap := DNSToAvroMap(schema)
		if OutputType == "kafka" {
			binary, err := codec.BinaryFromNative(nil, avroMap)
			confluentMessage := append(confluentAvroHeader, binary...)
			if err != nil {
				log.Fatalf("Failed to convert Go map to Avro binary data: %v", err)
			}
			producer.Producer.Input() <- &sarama.ProducerMessage{
				Topic: producer.Topic,
				Key:   sarama.StringEncoder(producer.MessageKey),
				Value: sarama.ByteEncoder(confluentMessage),
			}
		} else if OutputType == "stdout" {
			fmt.Printf("%s\n", avroMap)
		} else if OutputType == "file" {
			var values []map[string]interface{}
			values = append(values, avroMap)
			err = OCFWriter.Append(values)
			if err != nil {
				log.Fatalf("Error writing values to file: %v", err)
			}
			if err != nil {
				log.Fatalf("Failed to output AVRO to a file: %v", err)
			}
		}
	}
}

type AvroDnsSchema struct {
	Timestamp          int64                  `structs:"timestamp"`
	Udp                bool                   `structs:"udp"`
	IpVersion          int                    `structs:"ip_version"`
	SourceAddress      string                 `structs:"ip_src"`
	DestinationAddress string                 `structs:"ip_dst"`
	DestinationPort    int                    `structs:"dst_port"`
	Id                 int                    `structs:"txid"`
	Rcode              int                    `structs:"rcode"`
	Truncated          bool                   `structs:"truncated"`
	Response           bool                   `structs:"response"`
	RecursionDesired   bool                   `structs:"recursion_desired"`
	Answer             map[string]interface{} `structs:"answer"`
	Authority          map[string]interface{} `structs:"authority"`
	Additional         map[string]interface{} `structs:"additional"`
	Qname              string                 `structs:"qname"`
	Qtype              int                    `structs:"qtype"`
	Ttl                map[string]interface{} `structs:"ttl,omitempty"`
	Rname              map[string]interface{} `structs:"rname,omitempty"`
	Rtype              map[string]interface{} `structs:"rtype,omitempty"`
	Rdata              map[string]interface{} `structs:"rdata,omitempty"`
	EcsClient          map[string]interface{} `structs:"ecs_client,omitempty"`
	EcsSource          map[string]interface{} `structs:"ecs_source,omitempty"`
	EcsScope           map[string]interface{} `structs:"ecs_scope,omitempty"`
	Source             string                 `structs:"source"`
	Sensor             map[string]interface{} `structs:"sensor,omitempty"`
}

func DNSToAvroMap(schema *DnsSchema) map[string]interface{} {
	avroMap := AvroDnsSchema{
		Timestamp:          schema.Timestamp,
		SourceAddress:      schema.SourceAddress,
		DestinationAddress: schema.DestinationAddress,
		DestinationPort:    int(schema.DestinationPort),
		Id:                 int(schema.Id),
		Rcode:              schema.Rcode,
		Qtype:              int(schema.Qtype),
		Qname:              schema.Qname,
		RecursionDesired:   schema.RecursionDesired,
		Response:           schema.Response,
		Answer:             map[string]interface{}{"boolean": schema.Answer},
		Authority:          map[string]interface{}{"boolean": schema.Authority},
		Additional:         map[string]interface{}{"boolean": schema.Additional},
		Source:             schema.Source,
	}
	if schema.Rname != nil {
		avroMap.Rname = map[string]interface{}{"string": *schema.Rname}
	}
	if schema.Rtype != nil {
		avroMap.Rtype = map[string]interface{}{"int": int32(*schema.Rtype)}
	}
	if schema.Rdata != nil {
		avroMap.Rdata = map[string]interface{}{"string": *schema.Rdata}
	}
	if schema.Ttl != nil {
		avroMap.Ttl = map[string]interface{}{"long": int64(*schema.Ttl)}
	}
	if schema.EcsClient != nil {
		avroMap.EcsClient = map[string]interface{}{"string": *schema.EcsClient}
	}
	if schema.EcsSource != nil {
		avroMap.EcsSource = map[string]interface{}{"string": string(*schema.EcsSource)}
	}
	if schema.EcsScope != nil {
		avroMap.EcsScope = map[string]interface{}{"string": string(*schema.EcsScope)}
	}
	if schema.Source != "" {
		avroMap.Sensor = map[string]interface{}{"string": schema.Sensor}
	}

	if schema.Ipv4 {
		avroMap.IpVersion = 4
	} else {
		avroMap.IpVersion = 6
	}
	return structs.Map(avroMap)
}
