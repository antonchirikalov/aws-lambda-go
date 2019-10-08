package main

import (
	"encoding/json"
	"net/http"
	"os"

	"bitbucket.org/teachingstrategies/aws-lambda-go/internal/env"
	"bitbucket.org/teachingstrategies/aws-lambda-go/internal/tokens"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"

	"github.com/rs/zerolog/log"
)

type requestBody struct {
	TSIJwt string `json:"TSIJwt"`
}

type responseBody struct {
	Message string `json:"message,omitempty"`
	Iam     string `json:"iam,omitempty"`
	Refresh string `json:"refresh,omitempty"`
}

var (
	tokenGenerator     *tokens.TokenGenerator
	tsiJwtSharedSecret []byte
)

func init() {
	evs := env.FetchFromKMS("TSIJwtSharedSecret")
	tokenGenerator = tokens.NewGenerator("api.teachingstrategies.com", os.Getenv("Environment"))

	tsiJwtSharedSecret = []byte(evs.Get("TSIJwtSharedSecret"))
}

func main() {
	lambda.Start(exchangeToken)
}

func exchangeToken(req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {

	var reqBody requestBody

	failureRes, err := validateRequest(&req, &reqBody)
	if err != nil {
		return failureRes, err
	}

	gwsClaims, err := tokens.ParseTSIJwt(reqBody.TSIJwt, tsiJwtSharedSecret)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusForbidden,
		}, nil
	}

	tokenSet, err := tokenGenerator.ExchangeTSIJwt(gwsClaims)
	if err != nil {
		log.Error().Err(err).Msg("could not validate token")
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusUnprocessableEntity,
		}, nil
	}

	body := responseBody{
		Iam: tokenSet.Iam.Token,
		//Refresh: tokenSet.Refresh.Token,
	}

	jsn, err := json.Marshal(body)
	if err != nil {
		log.Error().Interface("body", body).Msg("could not create body")
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusOK,
		Body:       string(jsn),
		Headers:    tokenGenerator.PrepareTokenResponseHeaders(tokenSet),
	}, nil
}

func validateRequest(req *events.APIGatewayProxyRequest, reqBody *requestBody) (events.APIGatewayProxyResponse, error) {

	err := json.Unmarshal([]byte(req.Body), reqBody)

	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusUnprocessableEntity,
		}, nil
	}

	if len(reqBody.TSIJwt) == 0 {
		jsn, _ := json.Marshal(map[string][]string{
			"TSIJwt": {"Required"},
		})
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusBadRequest,
			Body:       string(jsn),
		}, nil
	}

	return events.APIGatewayProxyResponse{}, nil
}
