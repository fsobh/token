package main

import (
	"encoding/json"
	"log"
)

func toJSON(data interface{}) string {
	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal to JSON: %v", err)
	}
	return string(jsonBytes)
}

func main() {

}
