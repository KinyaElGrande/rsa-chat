package main

import (
	"fmt"
	"log"
	"os"

	"github.com/kinyaelgrande/chat-server/rsa"
	"github.com/spf13/cobra"
)

var keysGenCmd = &cobra.Command{
	Use:   "keys-gen",
	Short: "Generate RSA public/private key pairs",
	Long: `Generate RSA public/private key pairs and save them to files.

The keys will be saved in PEM format:
- Private key: private_key.pem (permissions: 0600)
- Public key: public_key.pem (permissions: 0644)`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := generateKeys(); err != nil {
			log.Fatalf("Error generating keys: %v", err)
		}
	},
}

var rootCmd = &cobra.Command{
	Use:   "rsaCli",
	Short: "A CLI tool for key management",
	Long:  `A command line tool for generating and managing RSA keys.`,
}

func init() {
	rootCmd.AddCommand(keysGenCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func generateKeys() error {
	keys, err := rsa.GenerateKeys()
	if err != nil {
		fmt.Println("Error generating keys:", err)
		os.Exit(1)
	}

	// create directory if it doesn't exist
	keyDir := "./keys"
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return err
	}

	// Save private key (restrictive permissions)
	if err := os.WriteFile(keyDir+"/private_key.pem", keys.PrivateKey, 0600); err != nil {
		return err
	}

	// Save public key (more open permissions)
	if err := os.WriteFile(keyDir+"/public_key.pem", keys.PublicKey, 0644); err != nil {
		return err
	}

	fmt.Printf("RSA key pair generated successfully!\n")

	return nil
}
