package main

import (
	"encoding/json"
	"net/http"
	"os"

	"bitbucket.org/teachingstrategies/aws-lambda-go/internal/keystore"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/rs/zerolog/log"
	"gopkg.in/go-playground/validator.v9"
)

var store keystore.Store
var validate *validator.Validate

type expectedPathParameters struct {
	KeyID string `validate:"required"`
}

func init() {
	env := os.Getenv("Environment")
	if env == "" {
		log.Fatal().Msg("could not determine environment")
	}
	store = keystore.NewSession(env)
	validate = validator.New()
}

func main() {
	lambda.Start(getPublicKey)
}

func getPublicKey(req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var res events.APIGatewayProxyResponse

	expected := expectedPathParameters{
		KeyID: req.PathParameters["keyID"],
	}

	err := validate.Struct(expected)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusBadRequest,
			Body:       err.Error(),
		}, nil
	}

	key := store.GetPublicIamKey(expected.KeyID)

	jsn, err := json.Marshal(key)
	if err != nil {
		log.Error().Err(err).Msg("could not marshal public key")
		return res, err
	}

	if len(key.KeyID) == 0 {
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusNotFound,
		}, nil
	}

	res.StatusCode = 200
	res.Body = string(jsn)
	return res, nil
}
