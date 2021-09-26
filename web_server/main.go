package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	verifier "github.com/okta/okta-jwt-verifier-golang"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"

	"github.com/wutka/cs6387_oauth_homework/common"
	oktaUtils "github.com/okta/samples-golang/okta-hosted-login/utils"
)

type TokenInfo struct {
	Error string `json:"error"`
	ErrorDescription string `json:"error_description"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	IdToken     string `json:"id_token"`
}

type UserInfo struct {
	Nonce string
	UserNumber int
}

var userMap = map[string]UserInfo{}
var config common.ConfigParams
var issuer string

var userCountLock sync.Mutex
var userCount = 1

func main() {
	config, _ = common.LoadConfig()

	issuer = fmt.Sprintf("https://%s/oauth2/default", config.OktaDomain)

	http.HandleFunc("/", handleMainPage)
	http.HandleFunc("/authorization-code/callback", handleAuthCode)

	http.ListenAndServe("localhost:8000", nil)
}

func incrementUserCount() int {
	userCountLock.Lock()
	defer userCountLock.Unlock()
	userCount += 1
	return userCount
}

func handleMainPage(w http.ResponseWriter, r *http.Request) {
	// Save a key associated with the user
	userKey := uuid.New()
	nonce, _ := oktaUtils.GenerateNonce()
	userInfo := UserInfo {
		UserNumber: incrementUserCount(),
		Nonce: nonce,
	}
	userMap[userKey.String()] = userInfo
	fmt.Printf("Using client id %s\n", config.ClientId)

	// Create the initial authorization request
	authURL := fmt.Sprintf("https://%s/oauth2/default/v1/authorize?client_id=%s&response_type=code&scope=openid&redirect_uri=http%%3A%%2F%%2Flocalhost%%3A8000%%2Fauthorization-code%%2Fcallback&state=%s&nonce=%s",
		config.OktaDomain, config.ClientId, userKey, nonce)
	w.Header().Set("Location", authURL)
	w.WriteHeader(http.StatusTemporaryRedirect)
}

func handleAuthCode(w http.ResponseWriter, r *http.Request) {
	// Retrieve the user's authorization code
	query := r.URL.Query()
	codes, ok := query["code"]
	if !ok {
		fmt.Printf("No code returned from OAUTH redirect")
		w.WriteHeader(500)
		return
	}
	code := codes[0]
	fmt.Printf("Got authorized user with code %s\n", code)

	// Retrieve the user state (the key for the local state map)
	states, ok := query["state"]
	if !ok {
		fmt.Printf("No state returned from OAUTH redirect")
		w.WriteHeader(500)
		return
	}
	state := states[0]

	userInfo := userMap[code]

	// Retrieve the authorization token
	tokenInfo, err := getAuthToken(code, userInfo.Nonce)
	if err != nil {
		fmt.Printf("Error fetching auth token: %+v\n", err)
		w.WriteHeader(500)
		return
	}

	// Get resource data from the other server based on authorization token
	_, err = getResourceData(tokenInfo, userInfo.Nonce)
	if err != nil {
		fmt.Printf("Error fetching resource data: %+v", err)
		w.WriteHeader(500)
		return
	}

	// Fetch the user state, which contains the user number
	user, ok := userMap[state]

	if ok {
		w.WriteHeader(200)
		w.Write([]byte(fmt.Sprintf("Welcome User %d", user.UserNumber)))
		return
	}
	w.WriteHeader(500)
	w.Write([]byte("Unknown user"))
}

func getAuthToken(code string, nonce string) (TokenInfo, error) {
	tokenInfo := TokenInfo{}

	// Set up request parameters
	formParams := url.Values{}
	formParams.Set("grant_type", "authorization_code")
	formParams.Set("redirect_uri", "http://localhost:8000/authorization-code/callback")
	formParams.Set("code", code)

	authHeader := base64.StdEncoding.EncodeToString(
		[]byte(config.ClientId + ":" + config.ClientSecret))

	client := http.Client{}

	addr := fmt.Sprintf("https://%s/oauth2/default/v1/token?%s", config.OktaDomain, formParams.Encode())
	req, _ := http.NewRequest("POST", addr, bytes.NewReader([]byte{}))

	// Send additional parameters as header values
	req.Header.Add("Authorization", "Basic "+authHeader)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Connection", "close")

	// Empty form data, other parameters passed as query values
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", "0")

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		return tokenInfo, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return tokenInfo, err
	}

	err = json.Unmarshal(body, &tokenInfo)
	if err != nil {
		return tokenInfo, nil
	}

	// Verify the id token
	if !verifyToken(tokenInfo.IdToken, nonce) {
		fmt.Printf("Invalid ID token\n")
		return tokenInfo, errors.New("invalid ID token")
	}
	return tokenInfo, err
}

func getResourceData(tokenInfo TokenInfo, nonce string) (common.ResourceData, error) {
	resourceData := common.ResourceData{}

	// Send a request to the other server with the user's authorization token
	addr := fmt.Sprintf("http://localhost:9000/getResourceData?token=%s&nonce=%s", tokenInfo.AccessToken, nonce)

	resp, err := http.Get(addr)
	if err != nil {
		return resourceData, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return resourceData, err
	}

	err = json.Unmarshal(body, &resourceData)
	return resourceData, err
}

func verifyToken(token string, nonce string) bool {
	// Verify the client ID in the token
	tokenVerification := map[string]string{
		"nonce": nonce,
		"aud":   config.ClientId,  // aud=clientID validates the id part of the token
	}

	// Create a verifier
	jv := verifier.JwtVerifier{
		Issuer:           issuer,
		ClaimsToValidate: tokenVerification,
	}

	// Run the verification
	result, err := jv.New().VerifyAccessToken(token)
	if err != nil {
		fmt.Printf("Error verifying access token: %+v\n", err)
		return false
	}

	if result != nil {
		fmt.Printf("ID Verification result: %+v\n", result)
	}

	return result != nil
}
