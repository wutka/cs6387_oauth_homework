package main

import (
	"encoding/json"
	"fmt"
	verifier "github.com/okta/okta-jwt-verifier-golang"
	"github.com/wutka/cs6387_oauth_homework/common"
	"net/http"
	"strconv"
)

var config common.ConfigParams
var nonce string
var issuer string

func main() {
	config, _ = common.LoadConfig()

	issuer = fmt.Sprintf("https://%s/oauth2/default", config.OktaDomain)

	http.HandleFunc("/getResourceData", handleGetResourceData)

	http.ListenAndServe("localhost:9000", nil)
}

func handleGetResourceData(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	// Retrieve the token from the query
	tokens, ok := query["token"]
	if !ok {
		fmt.Printf("No token in request")
		w.WriteHeader(500)
		return
	}
	token := tokens[0]

	// verify the token
	if !verifyToken(token) {
		fmt.Printf("Invalid auth token\n")
		w.WriteHeader(500)
		return
	}

	// Send an empty data structure back, any resource data would normally be stored here
	resourceData := common.ResourceData{}
	buff, _ := json.Marshal(&resourceData)
	w.Header().Set("Content-type", "application/json")
	w.Header().Set("Content-length", strconv.Itoa(len(buff)))
	w.WriteHeader(200)
	w.Write(buff)
	return

}

func verifyToken(token string) bool {
	// Verify the authorization token

	tokenVerification := map[string]string {
		"aud": "api://default",   // aud=api://default to verify authorization token
		"cid": config.ClientId,
	}

	// Create a verifier
	jv := verifier.JwtVerifier{
		Issuer:           issuer,
		ClaimsToValidate: tokenVerification,
	}

	// Verify the authorization token
	result, err := jv.New().VerifyAccessToken(token)
	if err != nil {
		fmt.Printf("Error verifying access token: %+v\n", err)
	}
	if result != nil {
		fmt.Printf("Access token result: %+v\n", result)
	}

	return result != nil
}

