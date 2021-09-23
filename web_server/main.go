package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/wutka/cs6387_oauth_homework/common"
)

type TokenInfo struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	IdToken     string `json:"id_token"`
}

var userMap = map[string]string{}
var config common.ConfigParams

var userCountLock sync.Mutex
var userCount = 1

func main() {
	config, _ = common.LoadConfig()

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
	userKey := uuid.New()
	userMap[userKey.String()] = fmt.Sprintf("User #%d", incrementUserCount())
	fmt.Printf("Using client id %s\n", config.ClientId)
	authURL := fmt.Sprintf("https://%s/oauth2/default/v1/authorize?client_id=%s&response_type=code&scope=openid&redirect_uri=http%%3A%%2F%%2Flocalhost:8000/authorization%%2Dcode%%2Fcallback&state=%s",
		config.OktaDomain, config.ClientId, userKey)
	w.Header().Set("Location", authURL)
	w.WriteHeader(http.StatusTemporaryRedirect)
}

func handleAuthCode(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	codes, ok := query["code"]
	if !ok {
		fmt.Printf("No code returned from OAUTH redirect")
		w.WriteHeader(500)
		return
	}
	code := codes[0]
	fmt.Printf("Got authorized user with code %s\n", code)

	states, ok := query["state"]
	if !ok {
		fmt.Printf("No state returned from OAUTH redirect")
		w.WriteHeader(500)
		return
	}
	state := states[0]

	tokenInfo, err := getAuthToken(code)
	if err != nil {
		fmt.Printf("Error fetching auth token: %+v\n", err)
		w.WriteHeader(500)
		return
	}

	_, err = getResourceData(tokenInfo)
	if err != nil {
		fmt.Printf("Error fetching resource data: %+v", err)
		w.WriteHeader(500)
		return
	}

	user, ok := userMap[state]

	if ok {
		w.WriteHeader(200)
		w.Write([]byte(fmt.Sprintf("Welcome back %s", user)))
		return
	}
	w.WriteHeader(500)
	w.Write([]byte("Unknown user"))
}

func getAuthToken(code string) (TokenInfo, error) {
	tokenInfo := TokenInfo{}

	addr := fmt.Sprintf("https://%s/oath2/default/v1/token", config.OktaDomain)
	formParams := url.Values{}
	formParams.Set("grant_type", "authorization_code")
	formParams.Set("redirect_url", "http://localhost:8000/authorization-code/callback")
	formParams.Set("code", code)

	encodedParams := formParams.Encode()

	authHeader := base64.StdEncoding.EncodeToString(
		[]byte(config.ClientId + ":" + config.ClientSecret))

	client := http.Client{}

	req, _ := http.NewRequest("POST", addr, strings.NewReader(encodedParams))

	req.Header.Add("Authorization", "Basic "+authHeader)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Connection", "close")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(encodedParams)))

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
	return tokenInfo, err
}

func getResourceData(tokenInfo TokenInfo) (common.ResourceData, error) {
	resourceData := common.ResourceData{}

	addr := fmt.Sprintf("http://localhost:9000/getResourceData?token=%s", tokenInfo.AccessToken)

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
