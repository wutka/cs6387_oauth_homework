package resource_server

import (
	"fmt"
	"github.com/wutka/cs6387_oauth_homework/common"
	"net/http"
)

var config common.ConfigParams

func main() {
	config, _ = common.LoadConfig()

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

}
