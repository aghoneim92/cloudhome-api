package main

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"context"
	"log"
	"os"

	firebase "firebase.google.com/go"

	"google.golang.org/api/iterator"

	bcrypt "golang.org/x/crypto/bcrypt"
)

func setupRouter(app *firebase.App) *gin.Engine {
	r := gin.Default()
	firestore, err := app.Firestore(context.Background())

	if err != nil {
		ErrorLogger.Printf("error initializing firestore: %v\n", err)
		return nil
	}

	r.POST("/authorize-mqtt-device", func(c *gin.Context) {
		var json struct {
			Username string `json:"username" binding:"required"`
			Password string `json:"password" binding:"required"`
		}

		if c.Bind(&json) == nil {
			documents := firestore.Collection("devices").Where("id", "==", json.Username).Documents(context.Background())
			doc, err := documents.Next()

			if err != nil {
				ErrorLogger.Printf("error getting document: %v\n", err)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
				return
			}

			passwordHash, ok := doc.Data()["passwordHash"].(string)
			if !ok {
				ErrorLogger.Println("error getting password hash")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
				return
			}
			if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(json.Password)); err != nil {
				ErrorLogger.Printf("error comparing password: %v\n", err)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"authorized": true})
			return
		}

		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
	})

	r.POST("/authorize-mqtt-superuser", func(c *gin.Context) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
	})

	r.POST("/acls", func(c *gin.Context) {
		var json struct {
			Username string `json:"username" binding:"required"`
			Topic    string `json:"topic" binding:"required"`
			ClientId string `json:"clientId" binding:"required"`
			Acc      int    `json:"acc" binding:"required"`
		}

		if c.Bind(&json) == nil {
			documents := firestore.Collection("devices").Where("id", "==", json.ClientId).Documents(context.Background())
			doc, err := documents.Next()

			if err == iterator.Done {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
				return
			}

			if err != nil {
				ErrorLogger.Printf("error getting document: %v\n", err)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
				return
			}

			id := doc.Ref.ID
			if id != strings.Split(json.Topic, "/")[1] {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"authorized": true})
		}

		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
	})

	return r
}

var (
	WarningLogger *log.Logger
	InfoLogger    *log.Logger
	ErrorLogger   *log.Logger
)

func init() {
	InfoLogger = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	WarningLogger = log.New(os.Stdout, "WARNING: ", log.Ldate|log.Ltime|log.Lshortfile)
	ErrorLogger = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
}

func main() {
	app, err := firebase.NewApp(context.Background(), nil)
	if err != nil {
		ErrorLogger.Printf("error initializing app: %v\n", err)
		return
	}
	r := setupRouter(app)
	// Listen and Server in 0.0.0.0:8080
	r.Run(":8080")
}
