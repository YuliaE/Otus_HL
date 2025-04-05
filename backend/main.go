package main

import (
	"bytes"
	"context"
	"db/db"
	"encoding/json"
	"io"
	"strconv"
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
	"github.com/gorilla/websocket"
	_ "github.com/lib/pq"
	amqp "github.com/rabbitmq/amqp091-go"
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
	User_id string `json:"id"`
	Post    string `json:"posttext"`
}

type newDialog struct {
	Receiver string `json:"userto"`
	Message  string `json:"dialogtext"`
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
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type Dialog struct {
	Sender   string `json:"userfrom"`
	Receiver string `json:"userto"`
	Message  string `json:"dialogtext"`
}

// DialogResponse представляет структуру ответа от API диалогов
type DialogResponse struct {
	DialogTime string `json:"dialogtime"`
}

func main() {

	router := gin.Default()

	// Middleware для логирования и установки X-Request-ID
	router.Use(
		// Установка X-Request-ID если не передан
		func(c *gin.Context) {
			requestID := c.GetHeader("X-Request-ID")
			if requestID == "" {
				requestID = uuid.New().String()
				c.Header("X-Request-ID", requestID)
			}
			c.Next()
		},
		// Логирование всех входящих запросов
		gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
			return fmt.Sprintf("[%s] %s %s %d %s | X-Request-ID: %s | Body: %s\n",
				param.TimeStamp.Format(time.RFC3339),
				param.Method,
				param.Path,
				param.StatusCode,
				param.Latency,
				param.Request.Header.Get("X-Request-ID"),
				getRequestBody(param.Request),
			)
		}),
		// Recovery middleware на случай паники
		gin.Recovery(),
	)

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
	router.POST("/dialog/:userId/send", dialogSend)
	//router.GET("/dialog/:userId/list", dialogList)
	router.GET("/post/feed/posted", handleWs)

	router.Run(":3000")

}

func failOnError(err error, msg string) {
	if err != nil {
		log.Panicf("%s: %s", msg, err)
	}
}

func getRequestBody(req *http.Request) string {
	if req.Body == nil {
		return ""
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return fmt.Sprintf("<error reading body: %v>", err)
	}

	// Восстанавливаем тело запроса для дальнейшего чтения
	req.Body = io.NopCloser(bytes.NewBuffer(body))

	return string(body)
}

func handleWs(c *gin.Context) {
	connWS, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to upgrade connection: %v", err)
		return
	}
	defer connWS.Close()

	_, message, err := connWS.ReadMessage()
	if err != nil {
		log.Printf("Error %s when reading message from client", err)
		return
	}
	user := strings.Trim(string(message), " ")

	log.Println("start responding to client...")
	i := 1
	for {
		amqpServerURL := os.Getenv("AMQP_SERVER_URL")
		//.conn, err := amqp.Dial("amqp://rmuser:rmpassword@rabbitmq1:5672/")
		conn, err := amqp.Dial(amqpServerURL)
		failOnError(err, "Failed to connect to RabbitMQ")
		defer conn.Close()

		ch, err := conn.Channel()
		failOnError(err, "Failed to open a channel")
		defer ch.Close()

		q, err := ch.QueueDeclare(
			user,  // name
			false, // durable
			false, // delete when unused
			false, // exclusive
			false, // no-wait
			nil,   // arguments
		)
		failOnError(err, "Failed to declare a queue")

		msgs, err := ch.Consume(
			q.Name, // queue
			"",     // consumer
			true,   // auto-ack
			false,  // exclusive
			false,  // no-local
			false,  // no-wait
			nil,    // args
		)
		for d := range msgs {
			response := fmt.Sprintf("Received a message: %s", d.Body)
			err = connWS.WriteMessage(websocket.TextMessage, []byte(response))

			if err != nil {
				log.Printf("Error %s when sending message to client", err)
				return
			}
		}

		i = i + 1
		time.Sleep(2 * time.Second)
	}
}

// callDialogAPI вызывает API диалогов с заданными параметрами
func callDialogAPI(request Dialog, requestID string) (*DialogResponse, error) {
	// URL API диалогов (замените на реальный URL)
	apiURL := "http://backenddialogs:3001/dialognew/send"
	// Преобразуем запрос в JSON
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}
	fmt.Printf("[OUTGOING] [%s] %s %s | Body: %s\n",
		time.Now().Format(time.RFC3339),
		"POST",
		apiURL,
		string(requestBody),
	)
	// Создаем HTTP-клиент с таймаутом
	client := &http.Client{
		Timeout: time.Second * 10,
	}

	// Создаем HTTP-запрос
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Устанавливаем заголовки
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", requestID)
	// Если нужно, добавьте аутентификацию
	// req.Header.Set("Authorization", "Bearer your-token")

	// Выполняем запрос
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call dialog API: %v", err)
	}
	defer resp.Body.Close()

	// Читаем ответ
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	//Парсим ответ
	var dialogResp DialogResponse
	if err := json.Unmarshal(body, &dialogResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return &dialogResp, nil
	//return body, nil
}

func dialogSend(c *gin.Context) {

	var req Dialog
	var oldreq newDialog

	//userFrom := c.Param("userId")
	requestID := c.GetHeader("X-Request-ID")
	if requestID == "" {
		requestID = uuid.New().String()
		c.Header("X-Request-ID", requestID)
	}

	if err := c.BindJSON(&oldreq); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}
	req.Sender = c.Param("userId")
	req.Receiver = oldreq.Receiver
	req.Message = oldreq.Message

	// Вызов API диалогов
	response, err := callDialogAPI(req, requestID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.IndentedJSON(http.StatusCreated, gin.H{"result": response})
}

func postFeed(c *gin.Context) {
	var postGet Post

	myKey := c.Query("id")

	db := db.InitDB()
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
}

func userSearch(c *gin.Context) {

	searchString := "%" + c.Query("search") + "%"
	fmt.Println(searchString)
	db := db.InitDB()
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
	db := db.InitDB()
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
	db := db.InitDB()
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

	db := db.InitDB()
	defer db.Close()
	if err := c.BindJSON(&newPost); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	stmt, err := db.Prepare("INSERT INTO posts(user_id, post) VALUES ($1, $2) RETURNING post_id")
	if err != nil {
		log.Panic(err)
		return
	}
	defer stmt.Close()

	err = stmt.QueryRow(newPost.User_id, newPost.Post).Scan(&postId)
	if err != nil {
		log.Panic(err)
		return
	}

	c.IndentedJSON(http.StatusCreated, gin.H{"Post created": postId})

	amqpServerURL := os.Getenv("AMQP_SERVER_URL")
	conn, err := amqp.Dial(amqpServerURL)

	if err != nil {
		log.Fatalf("unable to open connect to RabbitMQ server. Error: %s", err)
	}

	defer conn.Close()

	ch, err := conn.Channel()
	failOnError(err, "Failed to open a channel")
	defer ch.Close()

	q, err := ch.QueueDeclare(
		newPost.User_id, // name
		false,           // durable
		false,           // delete when unused
		false,           // exclusive
		false,           // no-wait
		nil,             // arguments
	)
	failOnError(err, "Failed to declare a queue")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	body := newPost.Post
	err = ch.PublishWithContext(ctx,
		"",     // exchange
		q.Name, // routing key
		false,  // mandatory
		false,  // immediate
		amqp.Publishing{
			ContentType: "text/plain",
			Body:        []byte(body),
		})
	failOnError(err, "Failed to publish a message")
	log.Printf(" [x] Sent %s\n", body)
}

func loginUser(c *gin.Context) {

	user, pass, hasAuth := c.Request.BasicAuth()
	fmt.Fprintln(os.Stdout, "{0} {1}", pass, hasAuth)

	db := db.InitDB()
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
