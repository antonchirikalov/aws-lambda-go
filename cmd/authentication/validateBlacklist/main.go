package main

import (
	"os"
	"strconv"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/rs/zerolog/log"

	"bitbucket.org/teachingstrategies/aws-lambda-go/internal/keystore"
	"bitbucket.org/teachingstrategies/go-svc-bootstrap/tokens"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

type tokenParseFunc func(string) (*jwt.Token, error)

// BlacklistValidator validates an API gateway validation request against an iam token blacklist
type BlacklistValidator struct {
	keyServerURL   string
	store          keystore.Store
	tokenParseFunc tokenParseFunc
}

var bv *BlacklistValidator

func getValidatorParams() (string, string) {
	var env, keyServerURL string
	if env = os.Getenv("Environment"); env == "" {
		log.Fatal().Msg("could not determine environment")
	}

	if keyServerURL = os.Getenv("KeyServerURL"); keyServerURL == "" {
		log.Fatal().Msg("KeyServerURL environment variable missing")
	}

	return env, keyServerURL
}

func main() {
	env, keyServerURL := getValidatorParams()
	bv = NewBlacklistValidator(env, keyServerURL)

	lambda.Start(bv.validateBlacklist)
}

// NewBlacklistValidator creates a new BlacklistValidator for the given env and key server
func NewBlacklistValidator(env, keyServerURL string) *BlacklistValidator {
	return &BlacklistValidator{
		keyServerURL: keyServerURL,
		store:        keystore.NewSession(env),
		tokenParseFunc: func(token string) (*jwt.Token, error) {
			return liveTokenParseFunc(token, keyServerURL)
		},
	}
}

// liveTokenParseFunc parses and validates a jwt token using live public keys stored in the database
func liveTokenParseFunc(tk, keyServerURL string) (*jwt.Token, error) {
	return jwt.Parse(tk, func(tk *jwt.Token) (interface{}, error) {
		kid, err := tokens.RetrieveKID(tk.Header)
		if err != nil {
			return nil, err
		}

		return tokens.RetrievePublicKey(keyServerURL, kid)
	})
}

// failedAuthorizerResponse returns a policy that denies the request.
// If userID is nonzero, it will be included as the PrincipalID in the response.
// If errorMessage is nonempty, it will be included in the response context.
func failedAuthorizerResponse(arn, errorMessage string, userID int) events.APIGatewayCustomAuthorizerResponse {
	context := make(map[string]interface{})

	if errorMessage != "" {
		context["stringKey"] = errorMessage
	}

	principalUserIDStr := "user"
	if userID != 0 {
		principalUserIDStr = strconv.Itoa(userID)
	}

	return events.APIGatewayCustomAuthorizerResponse{
		PrincipalID: principalUserIDStr,
		Context:     context,
		PolicyDocument: events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Action:   []string{"execute-api:Invoke"},
					Effect:   "Deny",
					Resource: []string{arn},
				},
			},
		},
	}
}

// successfulAuthorizerResponse returns a policy that allows the request to proceed.
func successfulAuthorizerResponse(arn string, userID int) events.APIGatewayCustomAuthorizerResponse {
	return events.APIGatewayCustomAuthorizerResponse{
		PrincipalID: strconv.Itoa(userID),
		PolicyDocument: events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Action:   []string{"execute-api:Invoke"},
					Effect:   "Allow",
					Resource: []string{arn},
				},
			},
		},
	}
}

// validateBlacklist grants access if the requesting userID is not present in the blacklist
func (v *BlacklistValidator) validateBlacklist(req events.APIGatewayCustomAuthorizerRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	token := iamTokenFromHeader(req.AuthorizationToken)
	parsed, err := v.tokenParseFunc(token)

	if err != nil {
		log.Error().Err(err).Msg("error parsing jwt token")

		return failedAuthorizerResponse(req.MethodArn, "error parsing jwt token", 0), err
	}

	var claims jwt.MapClaims
	var ok bool

	if claims, ok = parsed.Claims.(jwt.MapClaims); !ok || !parsed.Valid {
		return failedAuthorizerResponse(req.MethodArn, "invalid jwt token", 0), err
	}

	userIDStr := claims["sub"].(string)
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		log.Error().Err(err).Str("userIDIn", userIDStr).Msg("error parsing userID")

		return failedAuthorizerResponse(req.MethodArn, "invalid jwt token", 0), err
	}

	blacklistEntries, err := v.store.GetBlacklistEntriesByUserID(userID)
	if err != nil {
		if err == keystore.ErrNotFound {
			// user is not in the blacklist, allow access
			return successfulAuthorizerResponse(req.MethodArn, userID), nil
		}

		log.Error().Err(err).Msg("error retrieving blacklist entry")
		return failedAuthorizerResponse(req.MethodArn, "error retrieving blacklist entry", userID), err
	}

	issuedAt := claims["iat"].(float64)
	valid := true
	for _, entry := range blacklistEntries {
		if issuedAt <= float64(entry.NotBefore) {
			valid = false
			break
		}
	}

	if valid {
		// token was issued after all blacklist entries
		return successfulAuthorizerResponse(req.MethodArn, userID), nil
	}

	// default case is to deny
	return failedAuthorizerResponse(req.MethodArn, "user is not permitted", userID), nil
}

func iamTokenFromHeader(bearer string) string {
	if len(bearer) > 7 && strings.ToUpper(bearer[0:6]) == "BEARER" {
		return bearer[7:]
	}

	return bearer
}
