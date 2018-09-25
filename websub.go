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
//GOSUB and RETURN were keywords in certain old BASIC dialect programming languages that not supported structured functions.
//GOSUB was similar to a function call, but without the well-defined parameters and RETURN did not accepted return values.
//The scope of these parameters lived outsided the function call, somewhere in the program body.
//So GOSUB/RETURN keywords only cared about the call stack.
//
//In that sense this package works the same. In a fully stateless design, only the call (websub.Gosub) and return (websub.Return) are
//handled by this package, using JWT cookies and state (function call id).
package websub

import (
	"fmt"
	"net/http"
	"time"

	"gitlab.com/gopherburrow/jwt"
)

const (
	//DefaultCookieNamePrefix stores the default cookie name prefix that will be used if no savdreq.Config.SetCookieNamePrefix() method is called.
	DefaultCookieNamePrefix = "OriginalRequest-"
	DefaultTimeoutSeconds   = 300
)

//Config stores the configuration for a set of HTTP resources that will be protected against CSRF attacks.
type Config struct {
	//SecretFunc is a function that will be used to create the secret for the HMAC-SHA256 signature for the Web Subroutine JWT Token.
	//It can be used to rotate the secret, shared the between multiple instances of a Handler or even multiple server instances.
	//It MUST not return a nil secret or an empty one.
	SecretFunc       func(r *http.Request) []byte
	NoStateHandler   http.Handler
	cookieNamePrefix string
	queryParamName   string
	timeoutSeconds   int
}

func Gosub(w http.ResponseWriter, r *http.Request, targetURL string) error {

	var c *Config

	if r == nil {
	}

	if targetURL == "" {
	}

	if timeoutSeconds <= 0 {
	}

	//Create JWT Claims
	claims := map[string]interface{}{
		jwt.ClaimIssuedAt:       r.URL.String(),
		jwt.ClaimAudience:       targetUrl,
		jwt.ClaimExpirationTime: jwt.NumericDate(time.Now().Add(time.Duration(timeoutSeconds) * time.Second)),
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
		Name:   c.cookieNamePrefix,
		Value:  t,
		MaxAge: c.timeoutSeconds,
		Path:   targetURL, //TODO All URL fields must be tested
	}
	http.SetCookie(w, cookie)

	http.Redirect(w, r, targetUrl, http.StatusSeeOther)
	return nil
}

func Check(r *http.Request) error {
	var c *Config

	state := r.URL.Query().Get(c.queryParamName)

	if state == "" {
		return fmt.Errorf("")
	}

	for _, cookie := range r.Cookies() {
		if cookie.Name != c.cookieNamePrefix+state {
			continue
		}

		v := cookie.Value

		//Recover the secret handling errors.
		s, err := secret(c, r)
		if err != nil {
			return err
		}

		//Test if it is ours token (verifying the signature), and not a token created by an attacker.
		var claims map[string]interface{}
		if claims, err := jwt.ValidateHS256(v, s); err != nil {
			return ErrTokenSignatureMustMatch
		}

		expNumDate, ok := claims[jwt.ClaimExpirationTime].(int64)
		if !ok {
			return ErrTokenMissingExpField
		}

		expTime := jwt.Time(expNumDate)
		if time.Now().After(expTime) {
			return ErrTokenExpired
		}

		aud, ok := claims[jwt.ClaimExpirationTime].(string)
		if !ok {
			return ErrTokenMissingAudField
		}

		//TODO Test if aud is current URL

		iss, ok := claims[jwt.ClaimExpirationTime].(string)
		if !ok {
			return ErrTokenMissingIssField
		}

		//TODO Test if aud is current URL

		break
	}

}

func Return(w http.ResponseWriter, r *http.Request) error {
	if err := Check(r); err != nil {
		return err
	}

}

func secret(c *Config, r *http.Request) ([]byte, *WebError) {
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
