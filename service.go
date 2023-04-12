package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/streadway/amqp"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Record struct {
	ID        int64  `bson:"_id,omitempty"`
	Data      string `bson:"data"`
	Signature string `bson:"signature"`
}

type Keyring struct {
	keys        [][]byte
	keyUsageMap map[int]int64
	mux         sync.Mutex
}

func NewKeyring(keys [][]byte) *Keyring {
	keyring := &Keyring{
		keys:        keys,
		keyUsageMap: make(map[int]int64),
	}
	return keyring
}

func (kr *Keyring) GetLeastRecentlyUsedKey() ([]byte, error) {
	kr.mux.Lock()
	defer kr.mux.Unlock()

	if len(kr.keys) == 0 {
		return nil, errors.New("no keys available")
	}

	minTime := int64(0)
	minIndex := 0
	for i, key := range kr.keys {
		if usageTime, ok := kr.keyUsageMap[i]; !ok || usageTime < minTime {
			minTime = usageTime
			minIndex = i
		}
	}

	if minTime == 0 {
		kr.keyUsageMap[minIndex] = time.Now().Unix()
	} else {
		kr.keyUsageMap[minIndex] = time.Now().Unix()
	}

	return kr.keys[minIndex], nil
}

func SignRecords(records []Record, privateKey []byte) error {
	key, err := x509.ParsePKCS1PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %v", err)
	}

	for i := range records {
		hash := sha256.Sum256([]byte(records[i].Data))
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
		if err != nil {
			return fmt.Errorf("failed to sign record %d: %v", records[i].ID, err)
		}
		records[i].Signature = base64.StdEncoding.EncodeToString(signature)
	}

	return nil
}

func Sign(data string, privateKey []byte) (string, error) {
	key, err := x509.ParsePKCS1PrivateKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %v", err)
	}

	hash := sha256.Sum256([]byte(data))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign data: %v", err)
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

func SaveRecords(ctx context.Context, records []Record, coll *mongo.Collection) error {
	documents := make([]interface{}, len(records))
	for i, record := range records {
		documents[i] = record
	}
	_, err := coll.InsertMany(ctx, documents)
	if err != nil {
		return fmt.Errorf("failed to save records to database: %v", err)
	}
	return nil
}

func GetUnsignedRecords(ctx context.Context, batchSize int, coll *mongo.Collection) ([]Record, error) {
	opts := options.Find().SetLimit(int64(batchSize))
	filter := bson.M{"signature": ""}
	cursor, err := coll.Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve unsigned records: %v", err)
	}
	defer cursor.Close(ctx)

	var records []Record
	for cursor.Next(ctx) {
		var record Record
		if err := cursor.Decode(&record); err != nil {
			return nil, fmt.Errorf("failed to decode record: %v", err)
		}
		records = append(records, record)
	}

	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("error while retrieving unsigned records: %v", err)
	}

	return records, nil
}
func KeyManagementService(keyring *Keyring) {
	conn, err := amqp.Dial("amqp://guest:guest@localhost:5672/")
	if err != nil {
		log.Fatalf("Failed to connect to RabbitMQ: %v", err)
	}
	defer conn.Close()

	ch, err := conn.Channel()
	if err != nil {
		log.Fatalf("Failed to open a channel: %v", err)
	}
	defer ch.Close()

	queue, err := ch.QueueDeclare(
		"key-requests", // name
		false,          // durable
		false,          // delete when unused
		false,          // exclusive
		false,          // no-wait
		nil,            // arguments
	)
	if err != nil {
		log.Fatalf("Failed to declare a queue: %v", err)
	}

	msgs, err := ch.Consume(
		queue.Name, // queue
		"",         // consumer
		true,       // auto-ack
		false,      // exclusive
		false,      // no-local
		false,      // no-wait
		nil,        // args
	)
	if err != nil {
		log.Fatalf("Failed to register a consumer: %v", err)
	}

	for msg := range msgs {
		var batchSize int
		err := json.Unmarshal(msg.Body, &batchSize)
		if err != nil {
			log.Printf("Failed to decode message body: %v", err)
			continue
		}

		key, err := keyring.GetLeastRecentlyUsedKey()
		if err != nil {
			log.Printf("Failed to get key from keyring: %v", err)
			continue
		}

		response, err := json.Marshal(key)
		if err != nil {
			log.Printf("Failed to encode response message: %v", err)
			continue
		}

		err = ch.Publish(
			"",          // exchange
			msg.ReplyTo, // routing key
			false,       // mandatory
			false,       // immediate
			amqp.Publishing{
				ContentType:   "text/plain",
				CorrelationId: msg.CorrelationId,
				Body:          response,
			})
		if err != nil {
			log.Printf("Failed to send response message: %v", err)
		}
	}
}

func RecordSigningService(keyring *Keyring) {
	conn, err := amqp.Dial("amqp://guest:guest@localhost:5672/")
	if err != nil {
		log.Fatalf("Failed to connect to RabbitMQ: %v", err)
	}
	defer conn.Close()

	ch, err := conn.Channel()
	if err != nil {
		log.Fatalf("Failed to open a channel: %v", err)
	}
	defer ch.Close()

	reqQueue, err := ch.QueueDeclare(
		"key-requests", // name
		false,          // durable
		false,          // delete when unused
		false,          // exclusive
		false,          // no-wait
		nil,            // arguments
	)
	if err != nil {
		log.Fatalf("Failed to declare a queue: %v", err)
	}

	resQueue, err := ch.QueueDeclare(
		"key-responses", // name
		false,           // durable
		false,           // delete when unused
		false,           // exclusive
		false,           // no-wait
		nil,             // arguments
	)
	if err != nil {
		log.Fatalf("Failed to declare a queue: %v", err)
	}

	for {
		records, err := GetUnsignedRecords(context.Background(), 10, coll)
		if err != nil {
			log.Printf("Failed to retrieve unsigned records: %v", err)
			continue
		}

		if len(records) == 0 {
			log.Printf("All records signed")
			break
		}

		key, err := keyring.GetLeastRecentlyUsedKey()
		if err != nil {
			log.Printf("Failed to get key from keyring: %v", err)
			continue
			// TODO: Add logic to handle the case where all keys are in use
		}

		// Send key request message to key management service
		batchSize := len(records)
		body, err := json.Marshal(batchSize)
		if err != nil {
			log.Printf("Failed to encode message body: %v", err)
			continue
		}

		msg := amqp.Publishing{
			ContentType:   "text/plain",
			CorrelationId: uuid.New().String(),
			ReplyTo:       resQueue.Name,
			Body:          body,
		}

		err = ch.Publish(
			"",            // exchange
			reqQueue.Name, // routing key
			false,         // mandatory
			false,         // immediate
			msg,
		)
		if err != nil {
			log.Printf("Failed to send key request message: %v", err)
			continue
			// TODO: Add logic to handle the case where the message could not be sent
		}

		// Wait for key response message
		deliveries, err := ch.Consume(
			resQueue.Name, // queue
			"",            // consumer
			true,          // auto-ack
			false,         // exclusive
			false,         // no-local
			false,         // no-wait
			nil,           // args
		)
		if err != nil {
			log.Printf("Failed to register a consumer: %v", err)
			continue
			// TODO: Add logic to handle the case where the consumer could not be registered
		}

		var selectedKey []byte
		for delivery := range deliveries {
			if delivery.CorrelationId == msg.CorrelationId {
				err = json.Unmarshal(delivery.Body, &selectedKey)
				if err != nil {
					log.Printf("Failed to decode key response message body: %v", err)
					continue
				}
				break
			}
		}

		// Check if a key was received
		if selectedKey == nil {
			log.Printf("No key received")
			continue
			// TODO: Add logic to handle the case where no key was received
		}

		err = SignRecords(records, selectedKey)
		if err != nil {
			log.Printf("Failed to sign records: %v", err)
			continue
			// TODO: Add logic to handle the case where the records could not be signed
		}

		err = SaveRecords(context.Background(), records, coll)
		if err != nil {
			log.Printf("Failed to save signed records: %v", err)
			continue
			// TODO: Add logic to handle the case where the signed records could not be saved
		}

		// Mark key as used in keyring
		err = keyring.MarkKeyAsUsed(selectedKey)
		if err != nil {
			log.Printf("Failed to mark key as used: %v", err)
			continue
			// TODO: Add logic to handle the case where the key could not be marked as used
		}
	}
}

func main() {
	// Initialize the keyring with 100 private keys
	keys := make([][]byte, 100)
	for i := 0; i < 100; i++ {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		keys[i] = x509.MarshalPKCS1PrivateKey(key)
	}
	keyring := NewKeyring(keys)

	// Initialize the MongoDB collection with 100,000 records of random data
	err := InitializeRecords()
	if err != nil {
		log.Fatalf("Failed to initialize records: %v", err)
	}

	// Start the key management service and record signing service
	go KeyManagementService(keyring)
	go RecordSigningService(keyring)

	// Wait for the services to finish
	select {}
}
