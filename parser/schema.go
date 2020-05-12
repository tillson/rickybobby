package parser

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"rickybobby/producer"
	"strings"
	"sync"

	"github.com/Shopify/sarama"
	"github.com/hamba/avro"
	"github.com/hamba/avro/ocf"
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
	AvroCodec        avro.Schema
)

// JSON serialization only supports nullifying types that can accept nil.
// The ECS fields are pointers because they're nullable.
type DnsSchema struct {
	Timestamp          int64   `json:"timestamp" avro:"timestamp"`
	Sha256             string  `json:"sha256"`
	Udp                bool    `json:"udp" avro:"udp"`
	Ipv4               bool    `json:"ipv4"`
	SourceAddress      string  `json:"src_address" avro:"ip_src"`
	SourcePort         int     `json:"src_port"`
	DestinationAddress string  `json:"dst_address" avro:"ip_dst"`
	DestinationPort    int     `json:"dst_port" avro:"dst_port"`
	Id                 int     `json:"id" avro:"txid"`
	Rcode              int     `json:"rcode" avro:"rcode"`
	Truncated          bool    `json:"truncated" avro:"truncated"`
	Response           bool    `json:"response" avro:"response"`
	RecursionDesired   bool    `json:"recursion_desired" avro:"recursion_desired"`
	Answer             bool    `json:"answer"`
	Authority          bool    `json:"authority"`
	Additional         bool    `json:"additional"`
	Qname              string  `json:"qname" avro:"qname"`
	Qtype              int     `json:"qtype" avro:"qtype"`
	Ttl                *uint32 `json:"ttl"`
	Rname              *string `json:"rname"`
	Rtype              *uint16 `json:"rtype"`
	Rdata              *string `json:"rdata"`
	EcsClient          *string `json:"ecs_client"`
	EcsSource          *uint8  `json:"ecs_source"`
	EcsScope           *uint8  `json:"ecs_scope"`
	Source             string  `json:"source,omitempty" avro:"source"`
	Sensor             string  `json:"sensor,omitempty"`

	IPVersionAvro  int                    `avro:"ip_version"`
	AnswerAvro     map[string]interface{} `avro:"answer"`
	AuthorityAvro  map[string]interface{} `avro:"authority"`
	AdditionalAvro map[string]interface{} `avro:"additional"`
	TTLAvro        longUnion              `avro:"ttl,omitempty"`
	RnameAvro      stringUnion            `avro:"rname,omitempty"`
	RtypeAvro      intUnion               `avro:"rtype,omitempty"`
	RdataAvro      stringUnion            `avro:"rdata,omitempty"`
	EcsClientAvro  stringUnion            `avro:"ecs_client,omitempty"`
	EcsSourceAvro  stringUnion            `avro:"ecs_source,omitempty"`
	EcsScopeAvro   stringUnion            `avro:"ecs_scope,omitempty"`
	SensorAvro     stringUnion            `avro:"sensor,omitempty"`
}

type stringUnion struct {
	String string `avro:"string"`
}
type intUnion struct {
	Int int `avro:"int"`
}
type longUnion struct {
	Long int `avro:"long"`
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

// FormatOutputExport converts DnsSchema into suitable formats (avro/json) and
// writes them to the proper destination (stdout/file/kafka)
func FormatOutputExport(schema *DnsSchema) {
	if Format == "avro" {
		DnsSchemaToAvro(schema, ByteWriteChannel)
	} else if Format == "json" {
		jsonData, err := json.Marshal(&schema)
		if err != nil {
			log.Warnf("Error converting to JSON: %v", err)
		}
		WriteWaitGroup.Add(1)
		ByteWriteChannel <- jsonData
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
}

// WriteByteOutput consumes from the ByteWriteChannel and writes to the destination defined by OutputType.
func WriteByteOutput() {
	var schemaIdentifier uint32 = 3
	var schemaIdentifierBuffer []byte = make([]byte, 4)
	binary.BigEndian.PutUint32(schemaIdentifierBuffer, schemaIdentifier)
	schemaVersion := producer.SchemaVersion
	var confluentAvroHeader []byte = make([]byte, schemaVersion)

	var avroWriter = avro.NewWriter(OutputStream, 1000)
	if OutputType == "file" && Format == "avro" {
		var magicBytes = [4]byte{'O', 'b', 'j', 1}
		var HeaderSchema = ocf.HeaderSchema
		header := ocf.Header{
			Magic: magicBytes,
			Meta:  nil,
		}
		avroWriter.WriteVal(HeaderSchema, header)
	}

	buffered := 0
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
			len := len(bytes)
			buffered += len
			if buffered > 1000 {
				avroWriter.Flush()
				buffered = len
			}
			avroWriter.WriteBytes(bytes)
		}
		avroWriter.Flush()
		WriteWaitGroup.Done()
	}
}

// DnsSchemaToAvro converts DnsSchema to an avro buffer and sends it to the passed channel.
// It then releases the DnsSchema buffer to a global sync.Pool for recycling
func DnsSchemaToAvro(schema *DnsSchema, channel chan []byte) {

	schema.AnswerAvro = map[string]interface{}{"boolean": schema.Answer}
	schema.AuthorityAvro = map[string]interface{}{"boolean": schema.Authority}
	schema.AdditionalAvro = map[string]interface{}{"boolean": schema.Additional}

	if schema.Rname != nil {
		schema.RnameAvro = stringUnion{String: *schema.Rname}
	}
	if schema.Rtype != nil {
		schema.RtypeAvro = intUnion{Int: int(*schema.Rtype)}
	}
	if schema.Rdata != nil {
		schema.RdataAvro = stringUnion{String: *schema.Rdata}
	}
	if schema.Ttl != nil {
		schema.TTLAvro = longUnion{Long: int(*schema.Ttl)}
	}
	if schema.EcsClient != nil {
		schema.EcsClientAvro = stringUnion{String: *schema.EcsClient}
	}
	if schema.EcsSource != nil {
		schema.EcsSourceAvro = stringUnion{String: string(*schema.EcsSource)}
	}
	if schema.EcsScope != nil {
		schema.EcsScopeAvro = stringUnion{String: string(*schema.EcsScope)}
	}
	if schema.Source != "" {
		schema.SensorAvro = stringUnion{String: schema.Sensor}
	}

	if schema.Ipv4 {
		schema.IPVersionAvro = 4
	} else {
		schema.IPVersionAvro = 6
	}
	bytes, err := avro.Marshal(AvroCodec, schema)

	dnsSchemaPool.Put(schema)
	if err != nil {
		log.Fatal(err)
	}
	WriteWaitGroup.Add(1)
	channel <- bytes
}
