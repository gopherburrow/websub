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

//Package websub contains a Web GOSUB/RETURN mechanism in a server-stateless manner using JWT cookies and redirects.
//
//GOSUB and RETURN were keywords in certain old BASIC programming language dialects that not supported structured functions,
//and do not formalize any way the data is passed.
//In that sense this package works the same way. In a fully stateless design, only the call (websub.Gosub) and return (websub.Return) are
//handled by this package, using JWT cookies and a query parameter that identifies the call.
package websub

import (
	"errors"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"gitlab.com/gopherburrow/jwt"
)

const (
	//DefaultCookieNamePrefix stores the default cookie name prefix that will be used if no savdreq.Config.SetCookieNamePrefix() method is called.
	DefaultCookieName     = "Original-Request-"
	DefaultTraceParam     = "orig-req"
	DefaultTimeoutSeconds = 300
)

var (
	ErrRequestMustBeNonNil     = errors.New("websub: request must be non nil")
	ErrTargetURLMustBeNotEmpty = errors.New("websub: targetURL must be not empty")
	ErrTargetURLMustBeValid    = errors.New("websub: targetURL must be valid")
	ErrTokenSignatureMustMatch = errors.New("websub: token signature must match")
	ErrTokenMissingAudField    = errors.New("websub: token missing aud field")
	ErrRequestMustMatchAud     = errors.New("websub: request must match aud field")
	ErrTokenMissingIssField    = errors.New("websub: token missing iss field")
	ErrTokenExpired            = errors.New("websub: token expired")
	ErrTokenNotFound           = errors.New("websub: token not found")
	ErrSecretError             = errors.New("websub: the token secret cannot be empty ")
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
	TraceParam     string
	TimeoutSeconds int
}

func (wc *Config) Gosub(w http.ResponseWriter, r *http.Request, targetURL string) error {
	if r == nil {
		return ErrRequestMustBeNonNil
	}

	if targetURL == "" {
		return ErrTargetURLMustBeNotEmpty
	}

	parsedTargetURL, err := url.Parse(targetURL)
	if err != nil {
		return ErrTargetURLMustBeValid
	}

	if !parsedTargetURL.IsAbs() {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		parsedTargetURL.Scheme = scheme
		parsedTargetURL.Host = r.Host
	}

	traceParam := wc.TraceParam
	if traceParam == "" {
		traceParam = DefaultTraceParam
	}

	traceValue := strconv.FormatInt(rand.Int63(), 16)
	q := parsedTargetURL.Query()
	q.Add(traceParam, traceValue)
	parsedTargetURL.RawQuery = q.Encode()
	finalTargetURL := parsedTargetURL.String()

	parsedRequestURL := urlFromRequest(r)

	//Create JWT Claims
	claims := map[string]interface{}{
		jwt.ClaimIssuer:   parsedRequestURL.String(),
		jwt.ClaimAudience: finalTargetURL,
	}

	timeoutSeconds := wc.TimeoutSeconds
	if timeoutSeconds == 0 {
		timeoutSeconds = DefaultTimeoutSeconds
	}

	if timeoutSeconds > 0 {
		claims[jwt.ClaimExpirationTime] = jwt.NumericDate(time.Now().Add(time.Duration(timeoutSeconds) * time.Second))
	}

	//Recover the secret and handle errors.
	s, err := secret(wc, r)
	if err != nil {
		return err
	}

	t, err := jwt.CreateHS256(claims, s)
	if err != nil {
		return err
	}

	cookieName := wc.CookieName
	if cookieName == "" {
		cookieName = DefaultCookieName
	}

	var cookieDomain string
	if parsedTargetURL.IsAbs() {
		cookieDomain = parsedTargetURL.Hostname()
	}
	if cookieDomain == "" {
		cookieDomain = stripPort(r.Host)
	}

	cookie := &http.Cookie{
		Name:     cookieName + traceValue,
		Value:    t,
		Domain:   cookieDomain,
		Path:     parsedTargetURL.Path,
		HttpOnly: true,
		//FIXME Secure:   true,
	}
	if timeoutSeconds > 0 {
		cookie.MaxAge = timeoutSeconds
	}

	http.SetCookie(w, cookie)

	http.Redirect(w, r, finalTargetURL, http.StatusSeeOther)
	return nil
}

// func Refresh(w http.ResponseWriter, r *http.Request) error {
// 	if err := Check(r); err != nil {
// 		return err
// 	}

// }

//header("Expires: Sat, 26 Jul 1997 05:00:00

func (wc *Config) Return(w http.ResponseWriter, r *http.Request) error {
	returnURL, err := validateReturnURL(wc, r)
	if err != nil {
		return err
	}

	cookieName := wc.CookieName
	if cookieName == "" {
		cookieName = DefaultCookieName
	}

	traceParam := wc.TraceParam
	if traceParam == "" {
		traceParam = DefaultTraceParam
	}
	traceValue := r.URL.Query().Get(traceParam)

	cookieDomain := stripPort(r.Host)

	//Delete the Web Subroutine Cookie.
	cookie := &http.Cookie{
		Name:     cookieName + traceValue,
		Domain:   cookieDomain,
		Path:     r.URL.Path,
		HttpOnly: true,
		//FIXME Secure:   true,
		MaxAge: -1,
	}
	http.SetCookie(w, cookie)

	http.Redirect(w, r, returnURL, http.StatusSeeOther)
	return nil
}

func validateReturnURL(wc *Config, r *http.Request) (string, error) {
	cookieName := wc.CookieName
	if cookieName == "" {
		cookieName = DefaultCookieName
	}

	traceParam := wc.TraceParam
	if traceParam == "" {
		traceParam = DefaultTraceParam
	}
	traceValue := r.URL.Query().Get(traceParam)

	var cookie *http.Cookie
	for _, c := range r.Cookies() {
		if c.Name == cookieName+traceValue {
			cookie = c
			break
		}
	}

	if cookie == nil {
		return "", ErrTokenNotFound
	}

	v := cookie.Value

	//Recover the secret and handle errors.
	s, err := secret(wc, r)
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

	if aud, ok := audif.(string); ok && urlFromRequest(r).String() != aud {
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

func urlFromRequest(r *http.Request) *url.URL {
	parsedRequestURL := new(url.URL)
	*parsedRequestURL = *r.URL
	if !parsedRequestURL.IsAbs() {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		parsedRequestURL.Scheme = scheme
		parsedRequestURL.Host = r.Host
	}

	return parsedRequestURL
}

func secret(wc *Config, r *http.Request) ([]byte, error) {
	//Retrieve the Token secret (Custom or generated). Handle errors.
	if wc.Secret == nil {
		return nil, ErrSecretError
	}
	secret := wc.Secret(r)
	//It is part of the contract. Never return an empty secret. (Because it is no secret that way.)
	if secret == nil || len(secret) == 0 {
		return nil, ErrSecretError
	}

	return secret, nil
}
