package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"bitbucket.org/teachingstrategies/aws-lambda-go/internal/env"
	"bitbucket.org/teachingstrategies/aws-lambda-go/internal/tokens"
	"github.com/pkg/errors"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"

	"github.com/rs/zerolog/log"
)

type requestBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type responseBody struct {
	Message string `json:"message,omitempty"`
	Iam     string `json:"iam,omitempty"`
	//Refresh string `json:"refresh,omitempty"`
}

type gwsConfig struct {
	AuthToken    string
	AuthURI      string
	SharedSecret []byte
}

type gwsStandardResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
	Content struct {
		TSIJwt string `json:"TSIJwt"`
	} `json:"content"`
}

var (
	gws            gwsConfig
	tokenGenerator *tokens.TokenGenerator
)

func init() {
	vars := env.FetchFromKMS("GWSAuthURI", "GWSAuthorization", "TSIJwtSharedSecret")

	gws = gwsConfig{
		AuthToken:    vars.Get("GWSAuthorization"),
		AuthURI:      vars.Get("GWSAuthURI"),
		SharedSecret: []byte(vars.Get("TSIJwtSharedSecret")),
	}

	tokenGenerator = tokens.NewGenerator("api.teachingstrategies.com", os.Getenv("Environment"))
}

func main() {
	lambda.Start(generateTokens)
}

// Proxies credentials to GWS, returning a jwt for subsequent requests
func generateTokens(req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {

	var credentials requestBody

	failureRes, err := validateRequest(&req, &credentials)
	if err != nil {
		return failureRes, err
	}

	payload, err := json.Marshal(credentials)
	if err != nil {
		log.Error().Err(err).Msg("could not marshal credentials")
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, err
	}

	gwsResponse, err := proxyRequest(payload)
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, err
	}

	if gwsResponse.Status != 200 || gwsResponse.Content.TSIJwt == "" {
		return events.APIGatewayProxyResponse{StatusCode: gwsResponse.Status, Body: fmt.Sprintf("%s", gwsResponse.Message)}, nil
	}

	gwsClaims, err := tokens.ParseTSIJwt(gwsResponse.Content.TSIJwt, gws.SharedSecret)
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: http.StatusForbidden}, nil
	}

	tokenSet, err := tokenGenerator.ExchangeTSIJwt(gwsClaims)
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, nil
	}

	body := responseBody{
		Iam: tokenSet.Iam.Token,
		//Refresh: tokenSet.Refresh.Token,
	}

	jsn, err := json.Marshal(body)
	if err != nil {
		log.Error().Err(err).Interface("body", body).Msg("could not marshal body")
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusOK,
		Body:       string(jsn),
		Headers:    tokenGenerator.PrepareTokenResponseHeaders(tokenSet),
	}, nil
}

func validateRequest(req *events.APIGatewayProxyRequest, credentials *requestBody) (events.APIGatewayProxyResponse, error) {

	err := json.Unmarshal([]byte(req.Body), credentials)

	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusUnprocessableEntity,
		}, nil
	}

	failed := false
	failures := struct {
		Username []string `json:"username"`
		Password []string `json:"password"`
	}{}

	if len(credentials.Username) == 0 {
		failed = true
		failures.Username = []string{"Required"}
	}

	if len(credentials.Password) == 0 {
		failed = true
		failures.Password = []string{"Required"}
	}

	if failed {
		jsn, _ := json.Marshal(failures)
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusBadRequest,
			Body:       string(jsn),
		}, nil
	}

	return events.APIGatewayProxyResponse{}, nil
}

func proxyRequest(payload []byte) (gwsStandardResponse, error) {
	var gwsRes gwsStandardResponse

	request, err := http.NewRequest("POST", gws.AuthURI, strings.NewReader(string(payload)))
	if err != nil {
		return gwsRes, errors.WithMessage(err, "Unable to generate request proxy")

	}

	request.Header.Add("Authorization", gws.AuthToken)
	request.Header.Add("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(request)
	if err != nil || res == nil {
		return gwsRes, errors.WithMessagef(err, "unable to make proxy request to: %s", request.RequestURI)
	}

	defer func() {
		if err := res.Body.Close(); err != nil {
			log.Error().Err(err).Msg("unable to close body for gws proxy request")
		}
	}()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return gwsRes, errors.WithMessagef(err, "proxy response cannot be read: %+v", res.Body)
	}

	err = json.Unmarshal(body, &gwsRes)
	if err != nil {
		return gwsRes, errors.WithMessagef(err, "unexpected response format: %+v", body)
	}

	return gwsRes, nil
}
