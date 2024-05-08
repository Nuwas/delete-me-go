package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/gin-gonic/gin"
)

type Result struct {
	CodeChallenge string `json:"code-challenge" binding:"required"`
}

type CloudRequestMessage struct {
	Text string
}

func main() {

	secret := "Sample123"
	// Initialize HTTP server
	router := gin.Default()

	// Define an API endpoint to produce a Kafka message
	router.POST("/sample-app/v1/webhook", func(c *gin.Context) {

		//req.Header.Set("Content-Type", "application/json")
		//req.Header.Set("HPE-Webhook-Signature", signature)
		hpeWebhookSignature := c.Request.Header.Get("HPE-Webhook-Signature")

		//event := cloudevents.NewEvent()
		event := map[string]interface{}{}
		if err := c.ShouldBindJSON(&event); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		jsonString, err := json.Marshal(event)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		result := string(jsonString)

		fmt.Println("event", result)

		signature := computeHMAC([]byte(result), secret)
		if hpeWebhookSignature != signature {
			fmt.Printf("No signature match ")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to match signature, " + " " + hpeWebhookSignature + " #$# " + signature})
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "Success"})
	})

	//reqUrl := urlString + "?code-challenge=" + codeChallengeString
	// Define an API endpoint to produce a Kafka message
	router.GET("/sample-app/v1/webhook", func(c *gin.Context) {

		codeChallenge := c.Query("code-challenge")
		if &codeChallenge == nil || codeChallenge == "" {
			fmt.Printf("No codeChallenge :  %v, found to validate.", codeChallenge)
			c.JSON(http.StatusBadRequest, gin.H{"error": "No codeChallenge found."})
			return
		}
		fmt.Printf("received code-challenge : %s\n", codeChallenge)
		c.JSON(http.StatusOK, gin.H{"data": &Result{CodeChallenge: codeChallenge}})
	})

	// Start HTTP server
	go func() {
		if err := router.Run(":8080"); err != nil {
			fmt.Printf("Error starting HTTP server: %v\n", err)
			os.Exit(1)
		}
	}()

	// Graceful shutdown
	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, syscall.SIGINT, syscall.SIGTERM)
	<-sigchan

	fmt.Println("Shutting down gracefully...")
}

func computeHMAC(data []byte, secret string) string {
	hmac := hmac.New(sha256.New, []byte(secret))
	hmac.Write(data)
	return "sha256=" + hex.EncodeToString(hmac.Sum(nil))
}
