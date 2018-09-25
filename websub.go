// This file is part of Gopher Burrow Mux.
//
// Gopher Burrow Web Subroutine is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Gopher Burrow Web Subroutine is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Gopher Burrow Web Subroutine.  If not, see <http://www.gnu.org/licenses/>.

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
	"net/http"
	"time"

	"gitlab.com/gopherburrow/jwt"
)

const (
	//DefaultCookieNamePrefix stores the default cookie name prefix that will be used if no savdreq.Config.SetCookieNamePrefix() method is called.
	DefaultCookieNamePrefix = "SavedRequest-"
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
}

func Gosub(w http.ResponseWriter, r *http.Request, targetUrl string, timeoutSeconds int) error {

	var c *Config

	if r == null {
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
		MaxAge: timeoutSeconds,
	}
	http.SetCookie(w, cookie)

	return nil

}

func Check(w http.ResponseWriter, r *http.Request) error {

}

func Return() {

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
