package main

import (
	"encoding/json"
	"os"

	"bitbucket.org/teachingstrategies/aws-lambda-go/internal/keystore"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"

	"github.com/rs/zerolog/log"
)

var db keystore.Store

func init() {
	db = keystore.NewSession(os.Getenv("Environment"))
}

func main() {
	lambda.Start(getPublicKeys)
}

func getPublicKeys() (events.APIGatewayProxyResponse, error) {

	keys := db.GetPublicKeys()

	jsn, err := json.Marshal(keys)
	if err != nil {
		log.Fatal().Err(err).Msg("could not marshal public keys")
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       string(jsn),
	}, nil
}
