import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"sync"
	"time"

	"github.com/streadway/amqp"
)

type Record struct {
	ID        int    `bson:"_id,omitempty"`
	Data      string `bson:"data"`
	Signature string `bson:"signature"`
}

type KeyUsage struct {
	Key      string
	LastUsed time.Time
}

type Keyring struct {
	Keys  []string
	Usage map[string]time.Time
	Mutex sync.Mutex
}

func (k *Keyring) GetLeastRecentlyUsed() string {
	k.Mutex.Lock()
	defer k.Mutex.Unlock()

	var leastRecentlyUsedKey string
	var leastRecentlyUsedTime time.Time
	for _, key := range k.Keys {
		lastUsedTime, ok := k.Usage[key]
		if !ok || lastUsedTime.Before(leastRecentlyUsedTime) {
			leastRecentlyUsedKey = key
			leastRecentlyUsedTime = lastUsedTime
		}
	}

	k.Usage[leastRecentlyUsedKey] = time.Now()
	return leastRecentlyUsedKey
}

func SignRecords(records []Record, key string) {
	for i := range records {
		signature := Sign(records[i].Data, key)
		records[i].Signature = signature
	}

	SaveRecords(records)
}

func Sign(data string, key string) string {
	// Decode the private key from base64
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		panic(err)
	}

	// Parse the RSA private key
	privateKey, err := rsa.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		panic(err)
	}

	// Calculate the SHA-256 hash of the data
	hash := sha256.Sum256([]byte(data))

	// Sign the hash using the private key
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		panic(err)
	}

	// Encode the signature as base64 and return it
	return base64.StdEncoding.EncodeToString(signature)
}

func SaveRecords(records []Record) {
	// Convert the records to MongoDB documents
	var docs []interface{}
	for _, r := range records {
		docs = append(docs, r)
	}

	// Insert the documents into the MongoDB collection
	_, err := mongoCollection.InsertMany(context.Background(), docs)
	if err != nil {
		panic(err)
	}
}

func GetUnsignedRecords(batchSize int) []Record {
	// Find up to batchSize unsigned records from the MongoDB collection
	var unsignedRecords []Record
	filter := bson.M{"signature": ""}
	options := options.Find().SetLimit(int64(batchSize))
	cursor, err := mongoCollection.Find(context.Background(), filter, options)
	if err != nil {
		panic(err)
	}
	defer cursor.Close(context.Background())
	for cursor.Next(context.Background()) {
		var r Record
		err := cursor.Decode(&r)
		if err != nil {
			panic(err)
		}
		unsignedRecords = append(unsignedRecords, r)
	}
	if err := cursor.Err(); err != nil {
		panic(err)
	}
	return unsignedRecords
}
func KeyManagementService(broker string, keyring *Keyring) {
	// Connect to the RabbitMQ broker
	conn, err := amqp.Dial(broker)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Open a channel on the connection
	ch, err := conn.Channel()
	if err != nil {
		panic(err)
	}
	defer ch.Close()

	// Declare a queue for key requests
	q, err := ch.QueueDeclare(
		"key_requests",
		false, // durable
		false, // delete when unused
		false, // exclusive
		false, // no-wait
		nil,   // arguments
	)
	if err != nil {
		panic(err)
	}

	// Declare a queue for key responses
	r, err := ch.QueueDeclare(
		"key_responses",
		false, // durable
		false, // delete when unused
		false, // exclusive
		false, // no-wait
		nil,   // arguments
	)
	if err != nil {
		panic(err)
	}

	// Consume messages from the key request queue
	msgs, err := ch.Consume(
		q.Name, // queue
		"",     // consumer
		true,   // auto-ack
		false,  // exclusive
		false,  // no-local
		false,  // no-wait
		nil,    // args
	)
	if err != nil {
		panic(err)
	}

	for msg := range msgs {
		// Get the batch size from the message body
		batchSize, err := strconv.Atoi(string(msg.Body))
		if err != nil {
			panic(err)
		}

		// Get the least recently used key from the keyring
		key := keyring.GetLeastRecentlyUsed()

		// Send the key back in a response message
		err = ch.Publish(
			"",     // exchange
			r.Name, // routing key
			false,  // mandatory
			false,  // immediate
			amqp.Publishing{
				ContentType: "text/plain",
				Body:        []byte(key),
			},
		)
		if err != nil {
			panic(err)
		}

		// Wait for a short time to simulate key signing
		time.Sleep(time.Millisecond * 500)

		// Sign the next batch of records with the key
		unsignedRecords := GetUnsignedRecords(batchSize)
		SignRecords(unsignedRecords, key)

		// Log the signing
		log.Printf("Signed batch of %d records with key %s", len(unsignedRecords), key)
	}
}