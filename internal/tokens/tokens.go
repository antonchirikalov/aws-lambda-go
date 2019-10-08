package tokens

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"bitbucket.org/teachingstrategies/aws-lambda-go/internal/keystore"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

const (
	IAMDurationHours = 4
	//RefreshDurationHours = 24
	JSONTimeFormat = time.RFC3339
)

type TSIJwtClaims struct {
	Uid  int    `json:"uid"`
	Name string `json:"name"`
	jwt.StandardClaims
}

type iamClaims struct {
	Name string `json:"name"`
	jwt.StandardClaims
}

//type refreshClaims struct {
//	jwt.StandardClaims
//}

type TokenGenerator struct {
	db     keystore.Store
	Issuer string
}

type TokenSet struct {
	Iam *TokenWithExpiry
	//	Refresh *TokenWithExpiry
}

type TokenWithExpiry struct {
	Token     string
	ExpiresOn time.Time
}

func NewGenerator(issuer, environment string) *TokenGenerator {
	return &TokenGenerator{
		Issuer: issuer,
		db:     keystore.NewSession(environment),
	}
}

func (g *TokenGenerator) PrepareTokenResponseHeaders(tokens *TokenSet) map[string]string {

	return map[string]string{
		"Access-Control-Allow-Origin": "*",
		"Set-Cookie":                  makeTokenCookieHeader("iam", tokens.Iam).String(),
	}

}

func (g *TokenGenerator) ExchangeTSIJwt(gwsClaims TSIJwtClaims) (*TokenSet, error) {

	now := time.Now().UTC()

	iamToken, err := g.CreateIamToken(gwsClaims.Name, gwsClaims.Uid, now)
	if err != nil {
		log.Error().Err(err).Msg("could not create iam")
		return nil, err
	}

	return &TokenSet{
		Iam: iamToken,
		//Refresh: refreshToken,
	}, nil

}

func (g *TokenGenerator) CreateIamToken(name string, userID int, now time.Time) (*TokenWithExpiry, error) {

	key, err := g.db.GetRecentPrivateKey("iam")
	if err != nil {
		return nil, err
	}

	expiry := now.Add(time.Hour * time.Duration(IAMDurationHours))
	claims := prepareIamClaims(name, userID, now, g.Issuer, expiry)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	token.Header["kid"] = key.KeyID

	signedToken, err := token.SignedString(key.Private)
	if err != nil {
		return nil, err
	}

	return &TokenWithExpiry{
		Token:     signedToken,
		ExpiresOn: expiry,
	}, nil

}

func ParseTSIJwt(tsiJwt string, secret []byte) (TSIJwtClaims, error) {

	var gwsClaims TSIJwtClaims

	_, err := jwt.ParseWithClaims(tsiJwt, &gwsClaims, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	})

	if err != nil {
		log.Error().Err(err).Str("tsiJwt", tsiJwt).Msg("could not parse tsiJwt")
		return gwsClaims, err
	}

	return gwsClaims, nil
}

func (g *TokenGenerator) VerifyIAM(iam string) error {

	tkn, err := jwt.Parse(iam, g.getIamPublicKey)

	if err != nil || (tkn != nil && !tkn.Valid) {
		return errors.New("invalid token")
	}

	return nil

}

func (g *TokenGenerator) getIamPublicKey(tkn *jwt.Token) (interface{}, error) {

	kid, ok := tkn.Header["kid"]
	if !ok {
		return nil, jwt.ErrInvalidKey
	}

	key := g.db.GetPublicIamKey(kid.(string))

	return key.Public, nil
}

func makeTokenCookieHeader(name string, token *TokenWithExpiry) *http.Cookie {
	return &http.Cookie{
		Name:    name,
		Value:   token.Token,
		Path:    "/",
		Domain:  ".teachingstrategies.com",
		Expires: token.ExpiresOn,
	}
}

func prepareIamClaims(name string, userID int, now time.Time, iss string, expiresOn time.Time) iamClaims {
	return iamClaims{
		Name:           name,
		StandardClaims: prepareStandardClaim(userID, iss, now, expiresOn),
	}
}

//func prepareRefreshClaims(userID int, now time.Time, iss string, expiresOn time.Time) refreshClaims {
//	return refreshClaims{
//		StandardClaims: prepareStandardClaim(userID, iss, now, expiresOn),
//	}
//}

func prepareStandardClaim(userID int, iss string, now time.Time, expiresOn time.Time) jwt.StandardClaims {
	return jwt.StandardClaims{
		Id:        uuid.New().String(),
		IssuedAt:  now.Unix(),
		Issuer:    iss,
		NotBefore: now.Unix(),
		Subject:   strconv.Itoa(userID),
		ExpiresAt: expiresOn.Unix(),
	}
}
