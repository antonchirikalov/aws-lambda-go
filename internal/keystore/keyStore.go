package keystore

import (
	"crypto/rsa"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/dgrijalva/jwt-go"
	"github.com/rs/zerolog/log"
)

const JSONTimeFormat = time.RFC3339

// ErrNotFound is the error returned when a DynamoDB query returns no results
var ErrNotFound = fmt.Errorf("item(s) not found")

// Store provides functions for interacting with the key store
type Store interface {
	CreateBlacklistEntry(entry BlackListEntry) error
	GetBlacklistEntriesByUserID(userID int) ([]BlackListEntry, error)
	GetPublicIamKey(keyID string) *PublicKey
	GetPublicKeys() []*PublicKey
	GetRecentPrivateKey(keyType string) (*PrivateKey, error)
}

// DynamoStore implements the Store interface
type DynamoStore struct {
	*dynamodb.DynamoDB
	Tables storeTables
}

type storeTables struct {
	KeyStore       string
	TokenBlacklist string
}

// BlackListEntry is a single row in our refresh token blacklist
type BlackListEntry struct {
	UserID    int   `json:"userID"`
	NotBefore int64 `json:"notBefore"`
	TTL       int64 `json:"ttl"`
}

type PrivateKey struct {
	KeyID     string          `json:"keyID,omitempty"`
	CreatedOn JSONTime        `json:"createdOn"`
	SourceID  string          `json:"sourceID"`
	Private   *rsa.PrivateKey `json:"-"`
}

type PublicKey struct {
	KeyID        string         `json:"keyID,omitempty"`
	CreatedOn    JSONTime       `json:"createdOn"`
	SourceID     string         `json:"sourceID"`
	Public       *rsa.PublicKey `json:"-"`
	PKCS8Encoded string         `json:"key"`
}

type KeyRecord struct {
	KeyID     string `json:"keyID"`
	SourceID  string `json:"sourceID"`
	CreatedOn int64  `json:"createdOn"`
	Private   string `json:"private"`
	Public    string `json:"public"`
	Type      string `json:"type"`
}

// JSONTime converts serialized time.Time string into something better understood by humans
type JSONTime time.Time

func (t *JSONTime) UnmarshalJSON(b []byte) error {
	str := strings.Trim(string(b), `"`)
	effOn, err := time.Parse(JSONTimeFormat, str)
	if err != nil {
		return err
	}
	*t = JSONTime(effOn)
	return nil
}

func (t JSONTime) MarshalJSON() ([]byte, error) {
	ts := fmt.Sprintf("\"%s\"", t.String())
	return []byte(ts), nil
}

func (t JSONTime) Time() time.Time {
	return time.Time(t)
}

func (t JSONTime) String() string {
	return t.Time().Format(JSONTimeFormat)
}

func NewSession(environment string) Store {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	return &DynamoStore{
		DynamoDB: dynamodb.New(sess),
		Tables: storeTables{
			KeyStore:       fmt.Sprintf("%s.auth.KeyStore", environment),
			TokenBlacklist: fmt.Sprintf("%s.auth.TokenBlacklist", environment),
		},
	}
}

func (db *DynamoStore) GetRecentPrivateKey(keyType string) (*PrivateKey, error) {

	filter := expression.Key("type").Equal(expression.Value(keyType))

	projection := expression.NamesList(
		expression.Name("keyID"),
		expression.Name("sourceID"),
		expression.Name("createdOn"),
		expression.Name("private"),
		expression.Name("type"),
	)

	expr, err := expression.NewBuilder().WithKeyCondition(filter).WithProjection(projection).Build()
	if err != nil {
		log.Error().Fields(map[string]interface{}{
			"filter":     filter,
			"projection": projection,
		}).Msg("could not build expression")
	}

	input := &dynamodb.QueryInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		ProjectionExpression:      expr.Projection(),
		TableName:                 &db.Tables.KeyStore,
		KeyConditionExpression:    expr.KeyCondition(),
		Limit:                     aws.Int64(1),
		ScanIndexForward:          aws.Bool(false),
	}

	result, err := db.Query(input)

	if err != nil {
		log.Error().Interface("input", input).Msg("could not execute query")
		return nil, err
	}

	if *result.Count != 1 {
		log.Error().Interface("input", input).Msg("could not locate single key")
		return nil, err
	}

	var row KeyRecord
	err = dynamodbattribute.UnmarshalMap(result.Items[0], &row)
	if err != nil {
		log.Error().Interface("input", input).Msg("could not unmarshal key")
		return nil, err
	}

	pKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(row.Private))
	if err != nil {
		log.Error().Str("keyID", row.KeyID).Msg("could not parse private")
		return nil, err
	}

	return &PrivateKey{
		KeyID:     row.KeyID,
		CreatedOn: JSONTime(time.Unix(row.CreatedOn, 0)),
		SourceID:  row.SourceID,
		Private:   pKey,
	}, nil

}

func (db *DynamoStore) GetPublicIamKey(keyID string) *PublicKey {

	row := db.getPublicKey(keyID, "iam")
	return convertRowToPublicKey(row)

}

func (db *DynamoStore) getPublicKey(keyID string, keyType string) KeyRecord {

	var row KeyRecord

	keyFilter := expression.Key("type").Equal(expression.Value(keyType))
	condition := expression.Name("keyID").Equal(expression.Value(keyID))

	projection := expression.NamesList(
		expression.Name("keyID"),
		expression.Name("sourceID"),
		expression.Name("createdOn"),
		expression.Name("public"),
	)

	expr, err := expression.
		NewBuilder().
		WithKeyCondition(keyFilter).
		WithFilter(condition).
		WithProjection(projection).
		Build()

	if err != nil {
		log.Error().Fields(map[string]interface{}{
			"keyFilter":  keyFilter,
			"condition":  condition,
			"projection": projection,
		}).Msg("could not build expression")
	}

	input := &dynamodb.QueryInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		KeyConditionExpression:    expr.KeyCondition(),
		FilterExpression:          expr.Filter(),
		ProjectionExpression:      expr.Projection(),
		TableName:                 &db.Tables.KeyStore,
	}

	result, err := db.Query(input)
	if err != nil {
		log.Error().Interface("input", input).Msg("could not execute get item")
		return row
	}

	if *result.Count != 1 {
		return row
	}

	err = dynamodbattribute.UnmarshalMap(result.Items[0], &row)
	if err != nil {
		log.Error().Interface("input", input).Msg("could not unmarshal key row")
		return row
	}

	return row
}

func (db *DynamoStore) getPublicKeys() []KeyRecord {
	filter := expression.Name("type").Equal(expression.Value("iam"))

	projection := expression.NamesList(
		expression.Name("keyID"),
		expression.Name("sourceID"),
		expression.Name("createdOn"),
		expression.Name("public"),
	)

	expr, err := expression.NewBuilder().WithFilter(filter).WithProjection(projection).Build()
	if err != nil {
		log.Error().Fields(map[string]interface{}{
			"filter":     filter,
			"projection": projection,
		}).Msg("could not build expression")
	}

	input := &dynamodb.ScanInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		FilterExpression:          expr.Filter(),
		ProjectionExpression:      expr.Projection(),
		TableName:                 &db.Tables.KeyStore,
	}

	result, err := db.Scan(input)
	if err != nil {
		log.Error().Interface("input", input).Msg("could not execute scan")
		return nil
	}

	var rows []KeyRecord

	err = dynamodbattribute.UnmarshalListOfMaps(result.Items, &rows)
	if err != nil {
		log.Error().Interface("input", input).Msg("could not unmarshal key rows")
		return nil
	}

	return rows
}

func (db *DynamoStore) GetPublicKeys() []*PublicKey {

	rows := db.getPublicKeys()
	var keys []*PublicKey

	for _, row := range rows {
		keys = append(keys, convertRowToPublicKey(row))
	}

	return keys
}

func (db *DynamoStore) CreateBlacklistEntry(entry BlackListEntry) error {

	av, err := dynamodbattribute.MarshalMap(entry)
	if err != nil {
		return err
	}

	input := &dynamodb.PutItemInput{
		Item:      av,
		TableName: &db.Tables.TokenBlacklist,
	}

	_, err = db.PutItem(input)
	if err != nil {
		return err
	}

	return nil
}

// GetBlacklistEntriesByUserID retrieves all blacklist entry by userID
func (db *DynamoStore) GetBlacklistEntriesByUserID(userID int) ([]BlackListEntry, error) {
	input := &dynamodb.QueryInput{
		TableName: &db.Tables.TokenBlacklist,
		IndexName: aws.String("userID-index"),
		KeyConditions: map[string]*dynamodb.Condition{
			"userID": {
				ComparisonOperator: aws.String("EQ"),
				AttributeValueList: []*dynamodb.AttributeValue{
					&dynamodb.AttributeValue{
						N: aws.String(strconv.Itoa(userID)),
					},
				},
			},
		},
	}

	result, err := db.Query(input)
	if err != nil {
		log.Error().Err(err).Interface("input", input).Msg("error querying item")

		return nil, err
	}

	var entries []BlackListEntry

	if err = dynamodbattribute.UnmarshalListOfMaps(result.Items, &entries); err != nil {
		return nil, err
	}

	if len(entries) == 0 {
		// item was not found

		return nil, ErrNotFound
	}

	return entries, nil
}

func convertRowToPublicKey(row KeyRecord) *PublicKey {
	var key *rsa.PublicKey

	if len(row.Public) > 0 {
		parsedKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(row.Public))
		if err != nil {
			log.Fatal().Err(err).Fields(map[string]interface{}{
				"keyID":  row.KeyID,
				"public": row.Public,
			}).Msg("could not parse public key")
		}
		key = parsedKey
	}

	return &PublicKey{
		KeyID:        row.KeyID,
		CreatedOn:    JSONTime(time.Unix(row.CreatedOn, 0)),
		SourceID:     row.SourceID,
		Public:       key,
		PKCS8Encoded: row.Public,
	}
}
