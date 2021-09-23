package common

import (
	"encoding/json"
	"io/ioutil"
)

type ConfigParams struct {
	ClientId     string
	ClientSecret string
	OktaDomain   string
}

type ResourceData struct {
}

func LoadConfig() (ConfigParams, error) {
	config := ConfigParams{}

	configBytes, err := ioutil.ReadFile("config.json")
	if err != nil {
		return config, err
	}

	err = json.Unmarshal(configBytes, &config)
	if err != nil {
		return config, err
	}

	return config, nil
}
