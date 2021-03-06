package firebase

import (
	"errors"
	"time"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
)

// defaultAcceptableExpSkew is the default expiry leeway.
const defaultAcceptableExpSkew = 300 * time.Second

// certsCache to store certificate and prevent to not load every time from internet
// it need to implement cache timeout or use some Cache library (in-memory, memcache, redis)
var certsCache = make(map[string]*Certificates)

func verify(issuer, tokenString, clientCertURL string) (*Token, error) {
	decodedJWT, err := jws.ParseJWT([]byte(tokenString))
	if err != nil {
		return nil, err
	}
	decodedJWS, ok := decodedJWT.(jws.JWS)
	if !ok {
		return nil, errors.New("Firebase Auth ID Token cannot be decoded")
	}

	keys := func(j jws.JWS) ([]interface{}, error) {
		var certs *Certificates
		if item, ok := certsCache[clientCertURL]; ok {
			certs = item
		} else {
			certs = &Certificates{URL: clientCertURL}
			certsCache[clientCertURL] = certs
		}

		kid, ok := j.Protected().Get("kid").(string)
		if !ok {
			return nil, errors.New("Firebase Auth ID Token has no 'kid' claim")
		}
		cert, err := certs.Cert(kid)
		if err != nil {
			return nil, err
		}
		return []interface{}{cert.PublicKey}, nil
	}

	err = decodedJWS.VerifyCallback(keys,
		[]crypto.SigningMethod{crypto.SigningMethodRS256},
		&jws.SigningOpts{Number: 1, Indices: []int{0}})
	if err != nil {
		return nil, err
	}
	ks, _ := keys(decodedJWS)
	key := ks[0]
	if err := decodedJWT.Validate(key, crypto.SigningMethodRS256, validator(issuer)); err != nil {
		return nil, err
	}

	return &Token{delegate: decodedJWT}, nil
}

func validator(issuer string) *jwt.Validator {
	v := &jwt.Validator{}
	v.EXP = defaultAcceptableExpSkew
	v.SetAudience(firebaseAudience)
	v.SetIssuer(issuer)
	v.Fn = func(claims jwt.Claims) error {
		subject, ok := claims.Subject()
		if !ok || len(subject) == 0 || len(subject) > 128 {
			return jwt.ErrInvalidSUBClaim
		}
		return nil
	}
	return v
}
