package main

import (
	//"src/cache_time"
	"strconv"
	"strings"

	//memorycache "github.com/maxchagin/go-memorycache-example"
	"github.com/patrickmn/go-cache"

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

type newPost struct {
	Post string `json:"posttext"`
}

type getUser struct {
	User_id     string `json:"id"`
	First_name  string `json:"firstname"`
	Second_name string `json:"secondname"`
	Age         string `json:"age"`
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

type Post struct {
	PostId int
	Post   string
}

// Global variables
var jwtKey = []byte("my_secret_key")
var defaultExpiration = 5 * time.Minute
var cleanupInterval = 10 * time.Minute //cache time
var cacheOtus *cache.Cache             //variable for cache

func InitDB() *sql.DB {
	// Connection to master DB
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

func main() {

	cacheOtus = cache.New(defaultExpiration, cleanupInterval)
	//Add 1000 post from DB in cache
	InitCache(cacheOtus)

	router := gin.Default()
	users := router.Group("/users")
	users.Use(authMiddleware())
	{
		users.GET("/:id", getUserByID)
	}
	router.POST("/users/register", createUser)
	router.GET("/login", loginUser)
	router.GET("/users/search", userSearch)
	router.POST("/post/create", postCreate)
	router.GET("/post/feed", postFeed)
	router.Run(":3000")
}

func postFeed(c *gin.Context) {
	var postGet Post

	myKey := c.Query("id")
	post, err := cacheOtus.Get(myKey)

	if !err {
		db := InitDB()
		defer db.Close()

		num, err := strconv.Atoi(myKey)
		if err != nil {
			fmt.Println("Error converting string to int:", err)
		}

		if err := db.QueryRow("SELECT post_id, post FROM posts WHERE post_id = $1", num).Scan(&postGet.PostId, &postGet.Post); err != nil {
			if err == sql.ErrNoRows {
				c.IndentedJSON(http.StatusNotFound, gin.H{"Post not found": myKey})
			}
			c.IndentedJSON(http.StatusNotFound, gin.H{"Error": myKey})
		} else {
			c.IndentedJSON(http.StatusOK, gin.H{"Post from DB": postGet.Post})
		}
	} else {
		c.IndentedJSON(http.StatusOK, gin.H{"Post from cache": post})
	}
}

func InitCache(c *cache.Cache) {

	db := InitDB()
	defer db.Close()

	rows, err := db.Query("SELECT post_id, post FROM posts ORDER BY post_id DESC LIMIT 1000")
	if err != nil {
		log.Panic(err)
	}
	defer rows.Close()
	var a Post
	for rows.Next() {
		err := rows.Scan(&a.PostId, &a.Post)
		if err != nil {
			log.Panic(err)
		}
		c.Set(fmt.Sprint(a.PostId), a.Post, 5*time.Minute)
	}
}

func userSearch(c *gin.Context) {

	searchString := "%" + c.Query("search") + "%"
	fmt.Println(searchString)
	db := InitDB()
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
	db := InitDB()
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

func postCreate(c *gin.Context) {

	var newPost newPost
	var postId int

	db := InitDB()
	defer db.Close()
	if err := c.BindJSON(&newPost); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	stmt, err := db.Prepare("INSERT INTO posts(post) VALUES ($1) RETURNING post_id")
	if err != nil {
		log.Panic(err)
		return
	}
	defer stmt.Close()

	err = stmt.QueryRow(newPost.Post).Scan(&postId)
	if err != nil {
		log.Panic(err)
		return
	}

	//Add new post in cache
	cacheOtus.Set(fmt.Sprint(postId), newPost.Post, defaultExpiration)

	c.IndentedJSON(http.StatusCreated, gin.H{"Post created": postId})
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
