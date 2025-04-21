package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var jwtKey = []byte("secretkey")
var DB *gorm.DB

// ========== Models ==========
type User struct {
	gorm.Model
	Username string `json:"username" gorm:"unique"`
	Password string `json:"password"`
	Points   int    `json:"points"`
}

type WasteScan struct {
	gorm.Model
	UserID uint
	Amount int
}

type Redemption struct {
	gorm.Model
	UserID uint
	Item   string
	Points int
}

type Claims struct {
	Username string
	jwt.StandardClaims
}

// ========== Database ==========
func initDB() {
	var err error
	dsn := "root:@tcp(127.0.0.1:3306)/waste_monitoring?charset=utf8mb4&parseTime=True&loc=Local"
	DB, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("Failed to connect to MySQL database")
	}
	DB.AutoMigrate(&User{}, &WasteScan{}, &Redemption{})
}

// ========== Auth ==========
func register(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(user.Password), 14)
	user.Password = string(hashedPassword)

	if err := DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username already exists"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Registration successful"})
}

func login(c *gin.Context) {
	var creds User
	if err := c.ShouldBindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	var user User
	result := DB.First(&user, "username = ?", creds.Username)
	if result.Error != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: user.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			Subject:   user.Username,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(jwtKey)

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

// ========== Middleware ==========
func jwtMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			return
		}

		c.Set("username", claims.Username)
		c.Next()
	}
}

// ========== Clarifai ==========
func classifyWasteImage(imageURL string) (string, error) {
	apiKey := "d83885c3f26847aeb4e4b91fbe336e78"
	modelID := "general-image-recognition"

	url := "https://api.clarifai.com/v2/models/" + modelID + "/outputs"

	payload := map[string]interface{}{
		"inputs": []map[string]interface{}{
			{
				"data": map[string]interface{}{
					"image": map[string]string{
						"url": imageURL,
					},
				},
			},
		},
	}

	jsonPayload, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonPayload))
	req.Header.Add("Authorization", "Key "+apiKey)
	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	var response map[string]interface{}
	json.Unmarshal(body, &response)

	outputs := response["outputs"].([]interface{})
	data := outputs[0].(map[string]interface{})["data"].(map[string]interface{})
	concepts := data["concepts"].([]interface{})
	topConcept := concepts[0].(map[string]interface{})

	name := topConcept["name"].(string)
	return name, nil
}

func classifyImageHandler(c *gin.Context) {
	var req struct {
		ImageURL string `json:"image_url"`
	}

	if err := c.ShouldBindJSON(&req); err != nil || req.ImageURL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	label, err := classifyWasteImage(req.ImageURL)
	if err != nil {
		log.Println("Clarifai error:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to classify image"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"label": label})
}

// ========== Fitur Tambahan ==========
func scanWaste(c *gin.Context) {
	var req struct {
		Amount int `json:"amount"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Amount <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	username, _ := c.Get("username")
	var user User
	DB.First(&user, "username = ?", username)

	user.Points += req.Amount * 10
	DB.Save(&user)

	DB.Create(&WasteScan{UserID: user.ID, Amount: req.Amount})

	c.JSON(http.StatusOK, gin.H{"message": "Waste scanned successfully", "new_points": user.Points})
}

func redeemPoints(c *gin.Context) {
	var req struct {
		Item   string `json:"item"`
		Points int    `json:"points"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Points <= 0 || req.Item == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	username, _ := c.Get("username")
	var user User
	DB.First(&user, "username = ?", username)

	if user.Points < req.Points {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Not enough points"})
		return
	}

	user.Points -= req.Points
	DB.Save(&user)

	DB.Create(&Redemption{UserID: user.ID, Item: req.Item, Points: req.Points})

	c.JSON(http.StatusOK, gin.H{"message": "Redeemed successfully", "remaining_points": user.Points})
}

func getDashboard(c *gin.Context) {
	username, _ := c.Get("username")
	var user User
	DB.First(&user, "username = ?", username)

	c.JSON(http.StatusOK, gin.H{
		"message": "Welcome to the Waste Monitoring App!",
		"user":    user.Username,
		"points":  user.Points,
	})
}

// ========== Main ==========
func main() {
	initDB()
	r := gin.Default()

	r.POST("/register", register)
	r.POST("/login", login)
	r.POST("/classify-image", classifyImageHandler) // Endpoint AI baru

	auth := r.Group("/api")
	auth.Use(jwtMiddleware())
	{
		auth.GET("/dashboard", getDashboard)
		auth.POST("/scan-waste", scanWaste)
		auth.POST("/redeem", redeemPoints)
	}

	r.Run(":8080")
}
