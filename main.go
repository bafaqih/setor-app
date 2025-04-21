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
	Role     string `json:"role"` // Role: user / admin
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
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.StandardClaims
}

// ========== Database ==========
func initDB() {
	var err error
	dsn := "avnadmin:AVNS_SUTSVwEuBK0C9mHVVE_@tcp(setor-app-setor-app.h.aivencloud.com:26587)/waste_monitoring?charset=utf8mb4&parseTime=True&loc=Local"
	DB, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	DB.AutoMigrate(&User{}, &WasteScan{}, &Redemption{})
}

// ========== Auth ==========
func register(c *gin.Context) {
	var input User
	if err := c.ShouldBindJSON(&input); err != nil || input.Username == "" || input.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	newUser := User{
		Username: input.Username,
		Password: string(hashedPassword),
		Role:     "user",
	}

	if input.Role != "" {
		newUser.Role = input.Role
	}

	if err := DB.Create(&newUser).Error; err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Registration successful"})
}

func login(c *gin.Context) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&creds); err != nil || creds.Username == "" || creds.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	var user User
	if err := DB.First(&user, "username = ?", creds.Username).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	expiration := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: user.Username,
		Role:     user.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiration.Unix(),
			IssuedAt:  time.Now().Unix(),
			Subject:   user.Username,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString(jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenStr})
}

// ========== Middleware ==========
func jwtMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			return
		}

		c.Set("username", claims.Username)
		c.Set("role", claims.Role)
		c.Next()
	}
}

func adminOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, _ := c.Get("role")
		if role != "admin" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Admin access only"})
			return
		}
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
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}

	outputs := result["outputs"].([]interface{})
	data := outputs[0].(map[string]interface{})["data"].(map[string]interface{})
	concepts := data["concepts"].([]interface{})
	topConcept := concepts[0].(map[string]interface{})

	return topConcept["name"].(string), nil
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

	c.JSON(http.StatusOK, gin.H{"message": "Waste scanned", "new_points": user.Points})
}

func redeemPoints(c *gin.Context) {
	var req struct {
		Item   string `json:"item"`
		Points int    `json:"points"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Item == "" || req.Points <= 0 {
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
		"user":    user.Username,
		"role":    user.Role,
		"points":  user.Points,
		"message": "Welcome to the Waste Monitoring App!",
	})
}

func getAllUsers(c *gin.Context) {
	var users []User
	DB.Find(&users)
	c.JSON(http.StatusOK, users)
}

// ========== Main ==========
func main() {
	initDB()
	r := gin.Default()

	// Route untuk testing
	r.GET("/", func(c *gin.Context) {
		c.String(200, "Welcome to Setor App by Group-2")
	})

	r.GET("/test-register", func(c *gin.Context) {
		c.String(200, "TEST API Get Register")
	})

	r.GET("/test-login", func(c *gin.Context) {
		c.String(200, "TEST API Get Login")
	})

	r.GET("/test-classify-image", func(c *gin.Context) {
		c.String(200, "TEST API Get Classify Image")
	})

	r.GET("/api/test-dashboard", func(c *gin.Context) {
		c.String(200, "TEST API Get Dashboard")
	})

	r.GET("/api/test-scan-waste", func(c *gin.Context) {
		c.String(200, "TEST API Get Scan Waste")
	})

	r.GET("/api/test-redeem", func(c *gin.Context) {
		c.String(200, "TEST API Get Redeem)")
	})

	r.GET("/api/admin/test-users", func(c *gin.Context) {
		c.String(200, "TEST API Get Admin Users")
	})

	// Route asli
	r.POST("/register", register)
	r.POST("/login", login)
	r.POST("/classify-image", classifyImageHandler)

	auth := r.Group("/api")
	auth.Use(jwtMiddleware())
	{
		auth.GET("/dashboard", getDashboard)
		auth.POST("/scan-waste", scanWaste)
		auth.POST("/redeem", redeemPoints)

		admin := auth.Group("/admin")
		admin.Use(adminOnly())
		{
			admin.GET("/users", getAllUsers)
		}
	}

	r.Run(":8080")
}
