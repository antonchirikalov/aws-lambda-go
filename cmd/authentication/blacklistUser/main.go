package main

import (
	"encoding/json"
	"net/http"
	"os"
	"time"

	"bitbucket.org/teachingstrategies/aws-lambda-go/internal/keystore"
	"bitbucket.org/teachingstrategies/aws-lambda-go/internal/tokens"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"gopkg.in/go-playground/validator.v9"

	"github.com/rs/zerolog/log"
)

type requestBody struct {
	UserID      int               `json:"userID" validate:"min=1"`
	EffectiveOn keystore.JSONTime `json:"effectiveOn" validate:"required"`
}

var db keystore.Store
var validate *validator.Validate

func init() {
	db = keystore.NewSession(os.Getenv("Environment"))
	validate = validator.New()
}

func main() {
	lambda.Start(blackListHandler)
}

func blackListHandler(req *events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {

	var body requestBody

	err := json.Unmarshal([]byte(req.Body), &body)
	if err != nil {
		log.Error().Err(err).Msg("could unmarshal request body")
		return events.APIGatewayProxyResponse{StatusCode: http.StatusUnprocessableEntity}, nil
	}

	err = validate.Struct(body)
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: http.StatusBadRequest, Body: err.Error()}, nil
	}

	bl := keystore.BlackListEntry{
		UserID:    body.UserID,
		NotBefore: body.EffectiveOn.Time().Add(time.Hour * tokens.IAMDurationHours).Unix(),
		TTL:       time.Now().Add(time.Hour * tokens.IAMDurationHours).Unix(),
	}

	err = db.CreateBlacklistEntry(bl)
	if err != nil {
		log.Error().Err(err).Msg("could not save entry")
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, err
	}

	return events.APIGatewayProxyResponse{StatusCode: http.StatusCreated}, nil
}
