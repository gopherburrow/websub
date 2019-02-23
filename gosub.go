// This file is part of Gopher Burrow Web Subroutines.
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

//Package gosub contains a Web GOSUB/RETURN mechanism in a server-stateless manner using JWT cookies and redirects.
//
//GOSUB and RETURN were keywords in certain old BASIC programming language dialects that did not support structured functions,
//and did not formalize any way the data was passed (There were no parameters).
//In that sense this package works the same way. In a fully stateless design, only the call (gosub.Call) and return (gosub.Return) are
//handled by this package, using JWT cookies and a query parameter that identifies the call.
package gosub

import (
	"encoding/base64"
	"errors"
	"math/rand"
	"net/http"
	"net/url"
	"time"

	"gitlab.com/gopherburrow/jwt"
)

const (
	//DefaultCookieNamePrefix stores the default cookie name prefix that will be used if no gosub.Config.SetCookieNamePrefix() method is called.
	DefaultCookieNamePrefix = "State-"
	DefaultStateParam       = "state"
	DefaultTimeoutSeconds   = 120
)

var (
	ErrRequestMustBeNonNil     = errors.New("gosub: request must be non nil")
	ErrTargetURLMustBeNotEmpty = errors.New("gosub: targetURL must be not empty")
	ErrTargetURLMustBeValid    = errors.New("gosub: targetURL must be valid")
	ErrTokenSignatureMustMatch = errors.New("gosub: token signature must match")
	ErrTokenMissingAudField    = errors.New("gosub: token missing aud field")
	ErrRequestMustMatchAud     = errors.New("gosub: request must match aud field")
	ErrTokenMissingIssField    = errors.New("gosub: token missing iss field")
	ErrTokenExpired            = errors.New("gosub: token expired")
	ErrTokenNotFound           = errors.New("gosub: token not found")
	ErrSecretError             = errors.New("gosub: the token secret cannot be empty ")
)

func SetTransientPage(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
}

type Config struct {
	//SecretFunc is a function that will be used to create the secret for the HMAC-SHA256 signature for the Web Subroutine JWT Token.
	//It can be used to rotate the secret, shared the between multiple instances of a Handler or even multiple server instances.
	//It MUST be non nil and, when called, return NEITHER a nil secret NOR an empty one.
	Secret func(r *http.Request) []byte
	//CookieName stores a custom user defined cookie name prefix used to store the WebCall Token.
	//It can only be set in SetName(name) method.
	CookieName     string
	StateParam     string
	TimeoutSeconds int
}

func (c *Config) Call(w http.ResponseWriter, r *http.Request, targetURL string) error {
	if r == nil {
		return ErrRequestMustBeNonNil
	}

	if targetURL == "" {
		return ErrTargetURLMustBeNotEmpty
	}

	issURL := absolutizeURL(r.URL, getScheme(r), r.Host)

	audURL, err := url.Parse(targetURL)
	if err != nil {
		return ErrTargetURLMustBeValid
	}
	audURL = absolutizeURL(audURL, getScheme(r), r.Host)

	sv := make([]byte, 3)
	rand.Read(sv)
	stateValue := base64.RawURLEncoding.EncodeToString(sv)

	q := audURL.Query()
	q.Set(stateParam(c), stateValue)
	audURL.RawQuery = q.Encode()

	if err := createTokenCookie(c, w, r, issURL.String(), audURL.String(), stateValue); err != nil {
		return err
	}

	http.Redirect(w, r, audURL.String(), http.StatusTemporaryRedirect)
	return nil
}

func (c *Config) Return(w http.ResponseWriter, r *http.Request) error {
	iss, aud, err := validateAndIssAud(c, r)
	if err != nil {
		return err
	}

	audURL, err := url.Parse(aud)
	if err != nil {
		return err
	}

	stateValue := r.URL.Query().Get(stateParam(c))

	//Delete the Web Subroutine Cookie.
	cookie := &http.Cookie{
		Name:     cookieNamePrefix(c) + stateValue,
		Domain:   audURL.Hostname(),
		Path:     r.URL.Path,
		HttpOnly: true,
		//FIXME Secure:   true,
		MaxAge: -1,
	}
	http.SetCookie(w, cookie)

	http.Redirect(w, r, iss, http.StatusSeeOther)
	return nil
}

func (c *Config) IsValid(r *http.Request) bool {
	_, _, err := validateAndIssAud(c, r)
	return err != nil
}

func (c *Config) Refresh(w http.ResponseWriter, r *http.Request) error {
	iss, aud, err := validateAndIssAud(c, r)
	if err != nil {
		return err
	}

	stateValue := r.URL.Query().Get(stateParam(c))
	if err := createTokenCookie(c, w, r, iss, aud, stateValue); err != nil {
		return err
	}

	return nil
}

//header("Expires: Sat, 26 Jul 1997 05:00:00

func validateAndIssAud(c *Config, r *http.Request) (iss, aud string, err error) {
	stateValue := r.URL.Query().Get(stateParam(c))

	cookie, err := r.Cookie(cookieNamePrefix(c) + stateValue)
	if cookie == nil || err == http.ErrNoCookie {
		return "", "", ErrTokenNotFound
	}
	if err != nil {
		return "", "", err
	}
	v := cookie.Value

	//Recover the secret and handle errors.
	s, err := secret(c, r)
	if err != nil {
		return "", "", err
	}

	//Test if it is ours token (verifying the signature), and not a token created by an attacker.
	claims, err := jwt.ValidateHS256(v, s)
	if err != nil {
		return "", "", ErrTokenSignatureMustMatch
	}

	audif, ok := (*claims)[jwt.ClaimAudience]
	if !ok {
		return "", "", ErrTokenMissingAudField
	}

	if aud, ok := audif.(string); !ok || absolutizeURL(r.URL, getScheme(r), r.Host).String() != aud {
		return "", "", ErrRequestMustMatchAud
	}

	issif, ok := (*claims)[jwt.ClaimIssuer]
	if !ok {
		return "", "", ErrTokenMissingIssField
	}

	iss, ok = issif.(string)
	//TODO check iss Url

	if expNumDate, ok := (*claims)[jwt.ClaimExpirationTime].(int64); ok {
		if expTime := jwt.Time(expNumDate); time.Now().After(expTime) {
			return "", "", ErrTokenExpired
		}
	}

	return iss, aud, nil
}

func getScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func absolutizeURL(u *url.URL, scheme, host string) *url.URL {
	au := new(url.URL)
	*au = *u
	if au.IsAbs() {
		return au
	}
	au.Scheme = scheme
	au.Host = host
	return au
}

func cookieNamePrefix(c *Config) string {
	if c.CookieName == "" {
		return DefaultCookieNamePrefix
	}

	return c.CookieName
}

func stateParam(c *Config) string {
	if c.StateParam == "" {
		return DefaultStateParam
	}

	return c.StateParam
}

func createTokenCookie(c *Config, w http.ResponseWriter, r *http.Request, iss, aud, stateValue string) error {
	//Create JWT Claims
	claims := map[string]interface{}{
		jwt.ClaimIssuer:   iss,
		jwt.ClaimAudience: aud,
	}

	timeout := c.TimeoutSeconds
	if timeout == 0 {
		timeout = DefaultTimeoutSeconds
	}

	if timeout > 0 {
		claims[jwt.ClaimExpirationTime] = jwt.NumericDate(time.Now().Add(time.Duration(timeout) * time.Second))
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

	audURL, err := url.Parse(aud)
	if err != nil {
		return err
	}

	cookie := &http.Cookie{
		Name:     cookieNamePrefix(c) + stateValue,
		Value:    t,
		Domain:   audURL.Hostname(),
		Path:     audURL.Path,
		HttpOnly: true,
		//FIXME Secure:   true,
	}
	if timeout > 0 {
		cookie.MaxAge = timeout
	}

	http.SetCookie(w, cookie)
	return nil
}

func secret(c *Config, r *http.Request) ([]byte, error) {
	//Retrieve the Token secret (Custom or generated). Handle errors.
	if c.Secret == nil {
		return nil, ErrSecretError
	}
	secret := c.Secret(r)
	//It is part of the contract. Never return an empty secret. (Because it is no secret that way.)
	if secret == nil || len(secret) == 0 {
		return nil, ErrSecretError
	}

	return secret, nil
}
