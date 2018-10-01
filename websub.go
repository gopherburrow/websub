// This file is part of Gopher Burrow Mux.
//
// Gopher Burrow Web Subroutines is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Gopher Burrow Web Subroutines is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Gopher Burrow Web Subroutines.  If not, see <http://www.gnu.org/licenses/>.

//Package websub contains a Web GOSUB/RETURN mechanism in a server-stateless manner using JWT cookies and redirects.
//
//GOSUB and RETURN were keywords in certain old BASIC programming language dialects that not supported structured functions,
//and do not formalize any way the data is passed.
//In that sense this package works the same way. In a fully stateless design, only the call (websub.Gosub) and return (websub.Return) are
//handled by this package, using JWT cookies and a query parameter that identifies the call.
package websub

import (
	"errors"
	"net/http"
	"time"

	"gitlab.com/gopherburrow/jwt"
)

const (
	//DefaultCookieNamePrefix stores the default cookie name prefix that will be used if no savdreq.Config.SetCookieNamePrefix() method is called.
	DefaultCookieNamePrefix = "OriginalRequest-"
	DefaultTimeoutSeconds   = 300
)

var (
	ErrRequestMustBeNonNil     = errors.New("websub: request must be non nil")
	ErrConfigMustBeNonNil      = errors.New("websub: config must be non nil")
	ErrTokenSignatureMustMatch = errors.New("websub: token signature must match")
	ErrTokenMissingAudField    = errors.New("websub: token missing aud field")
	ErrRequestMustMatchAud     = errors.New("websub: request must match aud field")
	ErrTokenMissingIssField    = errors.New("websub: token missing iss field")
	ErrTokenExpired            = errors.New("websub: token expired")
	ErrTokenNotFound           = errors.New("websub: token not found")
	ErrSecretError             = errors.New("websub: the token secret cannot be empty ")
)

//Config stores the configuration for a set of HTTP resources that will be protected against CSRF attacks.
type Config struct {
	//SecretFunc is a function that will be used to create the secret for the HMAC-SHA256 signature for the Web Subroutine JWT Token.
	//It can be used to rotate the secret, shared the between multiple instances of a Handler or even multiple server instances.
	//It MUST be non nil and, when called, return NEITHER a nil secret NOR an empty one.
	SecretFunc     func(r *http.Request) []byte
	CookieName     func(r *http.Request) string
	TargetURL      func(r *http.Request) string
	TimeoutSeconds int
}

func Gosub(w http.ResponseWriter, r *http.Request, c *Config) error {
	if r == nil {
		return ErrRequestMustBeNonNil
	}

	if c == nil {
		return ErrConfigMustBeNonNil
	}

	targetURL := c.TargetURL(r)

	if targetURL == "" {
	}

	//TODO check target Url

	//Create JWT Claims
	claims := map[string]interface{}{
		jwt.ClaimIssuedAt: r.URL.String(),
		jwt.ClaimAudience: targetURL,
	}

	if c.TimeoutSeconds > 0 {
		claims[jwt.ClaimExpirationTime] = jwt.NumericDate(time.Now().Add(time.Duration(c.TimeoutSeconds) * time.Second))
	}

	//Recover the secret and handle errors.
	s, err := secret(c, r)
	if err != nil {
		return err
	}

	t, err := jwt.CreateHS256(claims, s)
	if err != nil {
		return err
	}

	cookie := &http.Cookie{
		Name:  c.CookieName(r),
		Value: t,
		Path:  targetURL, //TODO All URL fields must be tested
	}

	if c.TimeoutSeconds > 0 {
		cookie.MaxAge = c.TimeoutSeconds
	}

	http.SetCookie(w, cookie)

	http.Redirect(w, r, targetURL, http.StatusSeeOther)
	return nil
}

// func Refresh(w http.ResponseWriter, r *http.Request) error {
// 	if err := Check(r); err != nil {
// 		return err
// 	}

// }

func Return(w http.ResponseWriter, r *http.Request, c *Config) error {
	returnURL, err := validateReturnURL(r, c)
	if err != nil {
		return err
	}

	http.Redirect(w, r, returnURL, http.StatusSeeOther)
	return nil
}

func validateReturnURL(r *http.Request, c *Config) (string, error) {
	stackCookie := c.CookieName(r)

	for _, cookie := range r.Cookies() {
		if cookie.Name != stackCookie {
			continue
		}

		v := cookie.Value

		//Recover the secret and handle errors.
		s, err := secret(c, r)
		if err != nil {
			return "", err
		}

		//Test if it is ours token (verifying the signature), and not a token created by an attacker.
		claims, err := jwt.ValidateHS256(v, s)
		if err != nil {
			return "", ErrTokenSignatureMustMatch
		}

		audif, ok := (*claims)[jwt.ClaimAudience]
		if !ok {
			return "", ErrTokenMissingAudField
		}

		if aud, ok := audif.(string); ok && r.URL.String() != aud {
			return "", ErrRequestMustMatchAud
		}

		issif, ok := (*claims)[jwt.ClaimIssuer]
		if !ok {
			return "", ErrTokenMissingIssField
		}

		iss, ok := issif.(string)
		//TODO check iss Url

		if expNumDate, ok := (*claims)[jwt.ClaimExpirationTime].(int64); ok {
			if expTime := jwt.Time(expNumDate); time.Now().After(expTime) {
				return "", ErrTokenExpired
			}
		}

		return iss, nil
	}

	return "", ErrTokenNotFound
}

func secret(c *Config, r *http.Request) ([]byte, error) {
	//Retrieve the Token secret (Custom or generated). Handle errors.
	if c.SecretFunc == nil {
		return nil, ErrSecretError
	}
	secret := c.SecretFunc(r)
	//It is part of the contract. Never return an empty secret. (Because it is no secret that way.)
	if secret == nil || len(secret) == 0 {
		return nil, ErrSecretError
	}

	return secret, nil
}
