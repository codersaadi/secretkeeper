package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// loadConfig loads application configuration from file
func loadConfig() {
	data, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Println("Error reading config file:", err)
		return
	}

	if err := json.Unmarshal(data, &config); err != nil {
		fmt.Println("Error parsing config file:", err)
		return
	}
}

// saveConfig saves application configuration to file
func saveConfig() {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		fmt.Println("Error serializing config:", err)
		return
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil {
		fmt.Println("Error writing config file:", err)
		return
	}
}
