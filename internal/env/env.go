package env

import (
	"encoding/base64"
	"os"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/rs/zerolog/log"
)

type EnvironmentVariables map[string]string

func (e EnvironmentVariables) Get(v string) string {
	return (e)[v]
}

func Fetch(varNames ...string) EnvironmentVariables {

	evs := EnvironmentVariables{}

	for _, ev := range varNames {
		(evs)[ev] = os.Getenv(ev)
	}

	return evs
}

func FetchFromKMS(varNames ...string) EnvironmentVariables {

	evs := EnvironmentVariables{}

	sess := session.Must(session.NewSession())
	client := kms.New(sess)

	for _, ev := range varNames {
		t := os.Getenv(ev)

		decodedBytes, err := base64.StdEncoding.DecodeString(t)
		if err != nil || len(decodedBytes) == 0 {
			log.Error().Err(err).Fields(map[string]interface{}{
				"envVar": ev,
				"value":  t,
			}).Msg("could not decode env var")
		}

		input := &kms.DecryptInput{
			CiphertextBlob: decodedBytes,
		}

		response, err := client.Decrypt(input)
		if err != nil {
			log.Error().Err(err).Fields(map[string]interface{}{
				"envVar": ev,
				"input":  input,
			}).Msg("could not decrypt")
		}

		(evs)[ev] = string(response.Plaintext[:])
	}

	return evs

}
