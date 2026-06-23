package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	oktaverifier "github.com/okta/okta-jwt-verifier-golang"
)

var sessionStore = sessions.NewCookieStore([]byte(os.Getenv("OKTA_OAUTH2_SESSION_KEY")))

// Exchange is the Okta /v1/token response (ported from the sample).
type Exchange struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	Scope            string `json:"scope"`
	IdToken          string `json:"id_token"`
}

func main() {
	r := gin.Default()

	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "pong"})
	})

	r.GET("/", homeHandler)
	r.GET("/login", loginHandler)
	r.GET("/authorization-code/callback", callbackHandler)
	r.GET("/profile", profileHandler)
	r.GET("/logout", logoutHandler)

	serve(r)
}

// homeHandler == the sample's HomeHandler.
func homeHandler(c *gin.Context) {
	if isAuthenticated(c.Request) {
		c.Redirect(http.StatusFound, "/profile")
		return
	}
	c.String(http.StatusOK, "app-gin: visit /login to sign in with Okta")
}

// loginHandler == LoginHandler: build the /v1/authorize URL. state + nonce are
// stored in the session (the sample used package globals, which break with
// concurrent users).
func loginHandler(c *gin.Context) {
	state := generateRandom()
	nonce := generateRandom()

	session, _ := sessionStore.Get(c.Request, "okta-session")
	session.Values["state"] = state
	session.Values["nonce"] = nonce
	session.Save(c.Request, c.Writer)

	q := url.Values{}
	q.Add("client_id", os.Getenv("OKTA_OAUTH2_CLIENT_ID"))
	q.Add("response_type", "code")
	q.Add("response_mode", "query")
	q.Add("scope", "openid profile email")
	q.Add("redirect_uri", os.Getenv("OKTA_REDIRECT_URI"))
	q.Add("state", state)
	q.Add("nonce", nonce)

	authURL := os.Getenv("OKTA_OAUTH2_ISSUER") + "/v1/authorize?" + q.Encode()
	c.Redirect(http.StatusFound, authURL)
}

// callbackHandler == AuthCodeCallbackHandler: validate state, exchange the code,
// verify the ID token, then store the tokens in the session.
func callbackHandler(c *gin.Context) {
	session, _ := sessionStore.Get(c.Request, "okta-session")

	if c.Query("state") != session.Values["state"] {
		c.String(http.StatusBadRequest, "state did not match")
		return
	}

	exchange := exchangeCode(c.Query("code"))
	if exchange.Error != "" {
		c.String(http.StatusInternalServerError, "token exchange failed: %s", exchange.ErrorDescription)
		return
	}

	nonce, _ := session.Values["nonce"].(string)
	if _, err := verifyToken(exchange.IdToken, nonce); err != nil {
		c.String(http.StatusInternalServerError, "id_token verification failed: %v", err)
		return
	}

	session.Values["id_token"] = exchange.IdToken
	session.Values["access_token"] = exchange.AccessToken
	session.Save(c.Request, c.Writer)

	c.Redirect(http.StatusFound, "/profile")
}

// profileHandler == ProfileHandler: show the userinfo for the logged-in user.
func profileHandler(c *gin.Context) {
	if !isAuthenticated(c.Request) {
		c.Redirect(http.StatusFound, "/login")
		return
	}
	c.JSON(http.StatusOK, getProfileData(c.Request))
}

// logoutHandler == LogoutHandler: drop the tokens from the session.
func logoutHandler(c *gin.Context) {
	session, _ := sessionStore.Get(c.Request, "okta-session")
	delete(session.Values, "id_token")
	delete(session.Values, "access_token")
	session.Save(c.Request, c.Writer)
	c.Redirect(http.StatusFound, "/")
}

// exchangeCode == the sample's exchangeCode: POST the auth code to /v1/token
// with HTTP Basic auth (client_id:client_secret).
func exchangeCode(code string) Exchange {
	clientID := os.Getenv("OKTA_OAUTH2_CLIENT_ID")
	clientSecret := os.Getenv("OKTA_OAUTH2_CLIENT_SECRET")
	authHeader := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))

	q := url.Values{}
	q.Add("grant_type", "authorization_code")
	q.Add("code", code)
	q.Add("redirect_uri", os.Getenv("OKTA_REDIRECT_URI"))

	tokenURL := os.Getenv("OKTA_OAUTH2_ISSUER") + "/v1/token?" + q.Encode()
	req, _ := http.NewRequest("POST", tokenURL, bytes.NewReader([]byte("")))
	req.Header.Add("Authorization", "Basic "+authHeader)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Exchange{Error: "request_failed", ErrorDescription: err.Error()}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var exchange Exchange
	json.Unmarshal(body, &exchange)
	return exchange
}

// verifyToken == the sample's verifyToken: validate signature/issuer/audience
// and the nonce using Okta's JWT verifier.
func verifyToken(t, nonce string) (*oktaverifier.Jwt, error) {
	tv := map[string]string{}
	tv["nonce"] = nonce
	tv["aud"] = os.Getenv("OKTA_OAUTH2_CLIENT_ID")
	jv := oktaverifier.JwtVerifier{
		Issuer:           os.Getenv("OKTA_OAUTH2_ISSUER"),
		ClaimsToValidate: tv,
	}
	return jv.New().VerifyIdToken(t)
}

// getProfileData == the sample's getProfileData: call /v1/userinfo with the
// access token.
func getProfileData(r *http.Request) map[string]interface{} {
	m := make(map[string]interface{})

	session, _ := sessionStore.Get(r, "okta-session")
	accessToken, ok := session.Values["access_token"].(string)
	if !ok || accessToken == "" {
		return m
	}

	req, _ := http.NewRequest("GET", os.Getenv("OKTA_OAUTH2_ISSUER")+"/v1/userinfo", nil)
	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return m
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &m)
	return m
}

// isAuthenticated == the sample's isAuthenticated: a non-empty id_token in the
// session means the user is signed in.
func isAuthenticated(r *http.Request) bool {
	session, err := sessionStore.Get(r, "okta-session")
	if err != nil || session.Values["id_token"] == nil || session.Values["id_token"] == "" {
		return false
	}
	return true
}

// generateRandom produces the state/nonce values (16 random bytes, hex-encoded),
// matching the sample's generateState/GenerateNonce.
func generateRandom() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// serve starts HTTPS when the Let's Encrypt cert is mounted (prod/K3s),
// otherwise plain HTTP for local dev.
func serve(r *gin.Engine) {
	certFile := "/etc/letsencrypt/live/bakacore.com/fullchain.pem"
	keyFile := "/etc/letsencrypt/live/bakacore.com/privkey.pem"

	var err error
	if _, statErr := os.Stat(certFile); statErr == nil {
		log.Println("TLS cert found; serving HTTPS on :2096")
		err = r.RunTLS(":2096", certFile, keyFile)
	} else {
		log.Println("no TLS cert; serving HTTP on :2096")
		err = r.Run(":2096")
	}
	if err != nil {
		log.Fatalf("failed to run server: %v", err)
	}
}
