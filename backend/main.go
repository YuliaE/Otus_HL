package main

import (
	"strings"

	"database/sql" // add this
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type userSN struct {
	Firstname  string `json:"firstname"`
	Secondname string `json:"secondname"`
	Age        int    `json:"age"`
	Biography  string `json:"biography"`
	City       string `json:"city"`
	Login      string `json:"login"`
	Password   string `json:"password"`
}

type newLoginUSer struct {
	Id       string `json:"id"`
	Password string `json:"password"`
}

type getUser struct {
	User_id     string `json:"id"`
	First_name  string `json:"firstname"`
	Second_name string `json:"secondname"`
	Age         string `json:"Age"`
	Biography   string `json:"biography"`
	City        string `json:"city"`
}

type getUserSearch struct {
	User_id     string `json:"id"`
	First_name  string `json:"firstname"`
	Second_name string `json:"secondname"`
	Age         int    `json:"age"`
	City        string `json:"city"`
}

var jwtKey = []byte("my_secret_key")

func InitDB() *sql.DB {
	// Connection to master
	var db *sql.DB

	err := godotenv.Load()
	if err != nil {
		log.Panic("Error loading .env file")
	}

	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbUser := os.Getenv("DB_USER")
	dbPass := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")

	db, err = sql.Open("postgres", fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable", dbHost, dbUser, dbPass, dbName, dbPort))

	if err != nil {
		panic(err.Error())
	}

	err = db.Ping()
	if err != nil {
		panic(err.Error())
	}

	fmt.Println("Successfully connected to database")
	return db
}

func InitDBRep() *sql.DB {
	// Connection to master
	var db *sql.DB

	err := godotenv.Load()
	if err != nil {
		log.Panic("Error loading .env file")
	}

	dbHost := os.Getenv("DB_HOST_REP")
	dbPort := os.Getenv("DB_PORT_REP")
	dbUser := os.Getenv("DB_USER_REP")
	dbPass := os.Getenv("DB_PASSWORD_REP")
	dbName := os.Getenv("DB_NAME_REP")

	db, err = sql.Open("postgres", fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable", dbHost, dbUser, dbPass, dbName, dbPort))

	if err != nil {
		panic(err.Error())
	}

	err = db.Ping()
	if err != nil {
		panic(err.Error())
	}

	fmt.Println("Successfully connected to database")
	return db
}

func main() {

	router := gin.Default()
	users := router.Group("/users")
	users.Use(authMiddleware())
	{
		users.GET("/:id", getUserByID)
	}
	router.POST("/users/register", createUser)
	router.GET("/login", loginUser)
	router.GET("/users/search", userSearch)

	router.Run(":3000")
}
func userSearch(c *gin.Context) {

	searchString := "%" + c.Query("search") + "%"
	fmt.Println(searchString)
	db := InitDBRep()
	defer db.Close()

	rows, err := db.Query("SELECT user_id, first_name, second_name, age, city FROM users WHERE first_name like $1 order by user_id", searchString)
	if err != nil {
		log.Panic(err)
	}
	defer rows.Close()

	var userResult []getUserSearch
	for rows.Next() {
		var a getUserSearch
		err := rows.Scan(&a.User_id, &a.First_name, &a.Second_name, &a.Age, &a.City)
		if err != nil {
			log.Panic(err)
		}
		userResult = append(userResult, a)
	}
	c.IndentedJSON(http.StatusOK, userResult)
}

func getUserByID(c *gin.Context) {

	UserId, err := uuid.Parse(c.Param("id"))
	if err != nil {
		log.Panic(err)
	}
	fmt.Println(UserId)
	db := InitDBRep()
	defer db.Close()

	rows, err := db.Query("SELECT user_id, first_name, second_name, age, biography, city FROM users WHERE user_id = $1", UserId)
	if err != nil {
		log.Panic(err)
	}
	defer rows.Close()

	var userResult []getUser
	for rows.Next() {
		var a getUser
		err := rows.Scan(&a.User_id, &a.First_name, &a.Second_name, &a.Age, &a.Biography, &a.City)
		if err != nil {
			log.Panic(err)
		}
		userResult = append(userResult, a)
	}
	c.IndentedJSON(http.StatusOK, userResult)
}

func createUser(c *gin.Context) {

	var newUser userSN

	UserId := uuid.New()
	db := InitDB()
	defer db.Close()
	if err := c.BindJSON(&newUser); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	stmt, err := db.Prepare("INSERT INTO users (user_id, first_name, second_name, age, biography, city) VALUES ($1, $2, $3, $4, $5, $6)")
	if err != nil {
		log.Panic(err)
		return
	}
	defer stmt.Close()

	if _, err := stmt.Exec(UserId, newUser.Firstname, newUser.Secondname, newUser.Age, newUser.Biography, newUser.City); err != nil {
		log.Panic(err)
		return
	}
	// Save login and password
	hashedPass, _ := bcrypt.GenerateFromPassword([]byte(newUser.Password), 8)
	stmt, err = db.Prepare("INSERT INTO accounts (user_id, user_login, user_password) VALUES ($1, $2, $3)")
	if err != nil {
		log.Panic(err)
		return
	}
	defer stmt.Close()

	if _, err := stmt.Exec(UserId, newUser.Login, hashedPass); err != nil {
		log.Panic(err)
		return
	}

	c.IndentedJSON(http.StatusCreated, gin.H{"UserId": UserId.String()})
}

func loginUser(c *gin.Context) {

	user, pass, hasAuth := c.Request.BasicAuth()
	fmt.Fprintln(os.Stdout, "{0} {1}", pass, hasAuth)

	db := InitDB()
	defer db.Close()

	var userPassword string

	stmt := `SELECT user_password from accounts where user_login = $1`
	row := db.QueryRow(stmt, user)
	err := row.Scan(&userPassword)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusForbidden, user)
	} else {
		errHash := bcrypt.CompareHashAndPassword([]byte(userPassword), []byte(pass))
		if errHash != nil {
			c.JSON(http.StatusForbidden, user)
		} else {
			expirationTime := time.Now().Add(55 * time.Hour)
			claims := &jwt.StandardClaims{
				ExpiresAt: expirationTime.Unix(),
			}

			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			tokenString, err := token.SignedString(jwtKey)

			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"Token": tokenString})
		}
	}

}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := strings.Split(c.GetHeader("Authorization"), " ")[1]
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
			return
		}

		token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		if !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		c.Next()
	}
}
