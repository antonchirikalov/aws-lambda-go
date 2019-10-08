package main

import (
	"net/http"
	"os"
	"strings"

	"bitbucket.org/teachingstrategies/aws-lambda-go/internal/tokens"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

var tokenGenerator *tokens.TokenGenerator

func init() {
	tokenGenerator = tokens.NewGenerator("api.teachingstrategies.com", os.Getenv("Environment"))
}

func main() {
	lambda.Start(checkToken)
}

func checkToken(req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {

	res := events.APIGatewayProxyResponse{}

	tkn := strings.Split(req.Headers["Authorization"], "Bearer")

	if len(tkn) != 2 {
		res.StatusCode = http.StatusUnauthorized
		return res, nil
	}

	iam := strings.TrimSpace(tkn[1])

	if err := tokenGenerator.VerifyIAM(iam); err != nil {
		res.StatusCode = http.StatusUnauthorized
		return res, nil
	}

	res.StatusCode = http.StatusOK

	return res, nil
}