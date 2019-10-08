package main

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"bitbucket.org/teachingstrategies/aws-lambda-go/internal/keystore"
	"github.com/aws/aws-lambda-go/events"
	jwt "github.com/dgrijalva/jwt-go"
)

type blacklistEntryWithError struct {
	shouldError bool
	entries     []keystore.BlackListEntry
}

type StoreMock struct {
	keystore.Store
	blacklistValueMap map[int]blacklistEntryWithError
}

func (m StoreMock) GetBlacklistEntriesByUserID(userID int) ([]keystore.BlackListEntry, error) {
	resp, ok := m.blacklistValueMap[userID]

	if !ok {
		return nil, keystore.ErrNotFound
	}

	if resp.shouldError {
		return nil, errors.New("test error")
	}

	return resp.entries, nil
}

// returns a valid token that includes the "sub" claim for the given userID string
func testKeyFunc(testToken string) (*jwt.Token, error) {
	sub := testToken[2 : strings.Index(testToken[2:], "#")+2]
	iat, err := strconv.Atoi(testToken[strings.LastIndex(testToken, "#")+4:])
	if err != nil {
		return nil, err
	}

	return &jwt.Token{
		Claims: jwt.MapClaims{
			"sub": sub,
			"iat": float64(iat),
		},
		Valid: true,
	}, nil
}

func TestBlacklistValidator_validateBlacklist(t *testing.T) {
	const (
		userID  = 1164678 // MyTSOrgAdmin1
		testARN = "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/TestFunction/testStage/GET"
	)

	var validTestIAM = fmt.Sprintf("Bearer u#%d#iat%d", userID, time.Now().Unix())

	type fields struct {
		store          keystore.Store
		tokenParseFunc tokenParseFunc
	}
	type args struct {
		req events.APIGatewayCustomAuthorizerRequest
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   events.APIGatewayCustomAuthorizerResponse
	}{
		{
			name: "DENY - invalid token, validation fails",
			fields: fields{
				store: StoreMock{
					blacklistValueMap: map[int]blacklistEntryWithError{},
				},
				tokenParseFunc: func(_ string) (*jwt.Token, error) {
					return &jwt.Token{Valid: false}, nil
				},
			},
			args: args{events.APIGatewayCustomAuthorizerRequest{
				AuthorizationToken: validTestIAM,
				MethodArn:          testARN,
			}},
			want: unsucessfulTestResponse(0, testARN, "invalid jwt token"),
		},
		{
			name: "DENY - invalid token, sub is not a userID",
			fields: fields{
				store: StoreMock{
					blacklistValueMap: map[int]blacklistEntryWithError{},
				},
				tokenParseFunc: func(_ string) (*jwt.Token, error) {
					return &jwt.Token{
						Claims: jwt.MapClaims{
							"sub": "abc",
						},
						Valid: true,
					}, nil
				},
			},
			args: args{events.APIGatewayCustomAuthorizerRequest{
				AuthorizationToken: validTestIAM,
				MethodArn:          testARN,
			}},
			want: unsucessfulTestResponse(0, testARN, "invalid jwt token"),
		},
		{
			name: "DENY - invalid token, error while decoding",
			fields: fields{
				store: StoreMock{
					blacklistValueMap: map[int]blacklistEntryWithError{},
				},
				tokenParseFunc: func(_ string) (*jwt.Token, error) {
					return nil, errors.New("decode failure")
				},
			},
			args: args{events.APIGatewayCustomAuthorizerRequest{
				AuthorizationToken: "invalid token",
				MethodArn:          testARN,
			}},
			want: unsucessfulTestResponse(0, testARN, "error parsing jwt token"),
		},
		{
			name: "DENY - valid token, but error reaching dynamo",
			fields: fields{
				store: StoreMock{
					blacklistValueMap: map[int]blacklistEntryWithError{
						userID: {true, []keystore.BlackListEntry{
							{
								UserID:    userID,
								NotBefore: time.Now().Unix() + 1000,
							},
						},
						},
					},
				},
				tokenParseFunc: testKeyFunc,
			},
			args: args{events.APIGatewayCustomAuthorizerRequest{
				AuthorizationToken: validTestIAM,
				MethodArn:          testARN,
			}},
			want: unsucessfulTestResponse(userID, testARN, "error retrieving blacklist entry"),
		},
		{
			name: "ALLOW - valid iam token, no blacklist entry for user",
			fields: fields{
				store: StoreMock{
					blacklistValueMap: map[int]blacklistEntryWithError{},
				},
				tokenParseFunc: testKeyFunc,
			},
			args: args{events.APIGatewayCustomAuthorizerRequest{
				AuthorizationToken: validTestIAM,
				MethodArn:          testARN,
			}},
			want: successTestResponse(userID, testARN),
		},
		{
			name: "ALLOW - valid iam token, token was issued after blacklist",
			fields: fields{
				store: StoreMock{
					blacklistValueMap: map[int]blacklistEntryWithError{
						userID: {false, []keystore.BlackListEntry{
							{
								UserID:    userID,
								NotBefore: time.Now().Unix() - 1000,
							},
						},
						},
					},
				},
				tokenParseFunc: testKeyFunc,
			},
			args: args{events.APIGatewayCustomAuthorizerRequest{
				AuthorizationToken: validTestIAM,
				MethodArn:          testARN,
			}},
			want: successTestResponse(userID, testARN),
		},
		{
			name: "DENY - valid iam token, blacklist entry makes token invalid",
			fields: fields{
				store: StoreMock{
					blacklistValueMap: map[int]blacklistEntryWithError{
						userID: {false, []keystore.BlackListEntry{
							{
								UserID:    userID,
								NotBefore: time.Now().Unix() + 1000,
							},
						},
						},
					},
				},
				tokenParseFunc: testKeyFunc,
			},
			args: args{events.APIGatewayCustomAuthorizerRequest{
				AuthorizationToken: validTestIAM,
				MethodArn:          testARN,
			}},
			want: unsucessfulTestResponse(userID, testARN, "user is not permitted"),
		},
		{
			name: "DENY - valid iam token, fails on one single blacklist entry",
			fields: fields{
				store: StoreMock{
					blacklistValueMap: map[int]blacklistEntryWithError{
						userID: {false, []keystore.BlackListEntry{
							{
								UserID:    userID,
								NotBefore: time.Now().Unix() + 1000,
							},
							{
								UserID:    userID,
								NotBefore: time.Now().Unix() - 1000,
							},
							{
								UserID:    userID,
								NotBefore: time.Now().Unix() - 2000,
							},
						},
						},
					},
				},
				tokenParseFunc: testKeyFunc,
			},
			args: args{events.APIGatewayCustomAuthorizerRequest{
				AuthorizationToken: validTestIAM,
				MethodArn:          testARN,
			}},
			want: unsucessfulTestResponse(userID, testARN, "user is not permitted"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &BlacklistValidator{
				keyServerURL:   "/testurl",
				store:          tt.fields.store,
				tokenParseFunc: tt.fields.tokenParseFunc,
			}
			got, _ := v.validateBlacklist(tt.args.req)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("BlacklistValidator.validateBlacklist() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewBlacklistValidator(t *testing.T) {
	type args struct {
		env          string
		keyServerURL string
	}
	tests := []struct {
		name string
		args args
		want *BlacklistValidator
	}{
		{
			name: "creates struct with provided args",
			args: args{env: "unittest", keyServerURL: "https://abc.123"},
			want: &BlacklistValidator{
				keyServerURL: "https://abc.123",
				store:        keystore.NewSession("unittest"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewBlacklistValidator(tt.args.env, tt.args.keyServerURL)

			if got.keyServerURL != tt.args.keyServerURL {
				t.Errorf("NewBlacklistValidator() keyServerURL = %v, want %v", got.keyServerURL, tt.want.keyServerURL)
			}
		})
	}
}

func Test_getValidatorParams(t *testing.T) {
	type args struct {
		env          string
		keyServerURL string
	}
	tests := []struct {
		name    string
		args    args
		wantEnv string
		wantURL string
	}{
		{
			name:    "args from env variables",
			args:    args{env: "unittest", keyServerURL: "https://abc.123"},
			wantEnv: "unittest",
			wantURL: "https://abc.123",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("Environment", tt.args.env)
			os.Setenv("KeyServerURL", tt.args.keyServerURL)

			got, got1 := getValidatorParams()
			if got != tt.wantEnv {
				t.Errorf("getValidatorParams() gotEnv = %v, wantEnv %v", got, tt.wantEnv)
			}
			if got1 != tt.wantURL {
				t.Errorf("getValidatorParams() gotURL = %v, wantURL %v", got1, tt.wantURL)
			}
		})
	}
}

func successTestResponse(userID int, testARN string) events.APIGatewayCustomAuthorizerResponse {
	return events.APIGatewayCustomAuthorizerResponse{
		PrincipalID: principalID(userID),
		PolicyDocument: events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Action:   []string{"execute-api:Invoke"},
					Effect:   "Allow",
					Resource: []string{testARN},
				},
			},
		},
	}
}

func unsucessfulTestResponse(userID int, testARN, failureReason string) events.APIGatewayCustomAuthorizerResponse {
	return events.APIGatewayCustomAuthorizerResponse{
		PrincipalID: principalID(userID),
		Context: map[string]interface{}{
			"stringKey": failureReason,
		},
		PolicyDocument: events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Action:   []string{"execute-api:Invoke"},
					Effect:   "Deny",
					Resource: []string{testARN},
				},
			},
		},
	}
}

func principalID(userID int) string {
	if userID == 0 {
		return "user"
	}

	return strconv.Itoa(userID)
}
