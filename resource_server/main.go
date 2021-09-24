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
	tokens, ok := query["token"]
	if !ok {
		fmt.Printf("No token in request")
		w.WriteHeader(500)
		return
	}
	token := tokens[0]

	if !verifyToken(token) {
		fmt.Printf("Invalid auth token\n")
		w.WriteHeader(500)
		return
	}


	resourceData := common.ResourceData{}
	buff, _ := json.Marshal(&resourceData)
	w.Header().Set("Content-type", "application/json")
	w.Header().Set("Content-length", strconv.Itoa(len(buff)))
	w.WriteHeader(200)
	w.Write(buff)
	return

}
func verifyToken(token string) bool {
	tokenVerification := map[string]string {
		"aud": "api://default",
		"cid": config.ClientId,
	}

	jv := verifier.JwtVerifier{
		Issuer:           issuer,
		ClaimsToValidate: tokenVerification,
	}

	result, err := jv.New().VerifyAccessToken(token)
	if err != nil {
		fmt.Printf("Error verifying access token: %+v\n", err)
	}
	if result != nil {
		fmt.Printf("Access token result: %+v\n", result)
	}

	return result != nil
}

