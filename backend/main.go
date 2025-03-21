package main

import (
	"context"
	"db/db"
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
	"github.com/redis/go-redis/v9"
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

type getDialog struct {
	Dialog_id   string `json:"id"`
	User_from   string `json:"userfrom"`
	User_to     string `json:"userto"`
	Dialog_text string `json:"text"`
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
	Sender    string
	Receiver  string
	Message   string
	Timestamp time.Time
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
	router.POST("/post/create", postCreate)
	router.GET("/post/feed", postFeed)
	router.POST("/dialog/:userId/send", dialogSend)
	router.GET("/dialog/:userId/list", dialogList)
	router.GET("/post/feed/posted", handleWs)

	router.Run(":3000")

}

func failOnError(err error, msg string) {
	if err != nil {
		log.Panicf("%s: %s", msg, err)
	}
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

// FindDialogsByUserRedisFunction ищет диалоги по пользователю с пагинацией
func FindDialogsByUserRedisFunction(client *redis.Client, username string, cursor uint64, limit int) (uint64, []Dialog, error) {
	ctx := context.Background()

	// Вызываем загруженную функцию с помощью FCALL
	res, err := client.FCall(ctx, "find_dialogs", []string{username}, cursor, limit).Result()
	if err != nil {
		return 0, nil, err
	}

	// Преобразуем результат
	if result, ok := res.([]interface{}); ok && len(result) == 2 {
		newCursor := uint64(result[0].(int64))
		dialogsData := result[1].([]interface{})

		var dialogs []Dialog
		for _, item := range dialogsData {
			if dialogData, ok := item.([]interface{}); ok {
				dialog := Dialog{}
				for i := 0; i < len(dialogData); i += 2 {
					key := dialogData[i].(string)
					value := dialogData[i+1].(string)

					switch key {
					case "sender":
						dialog.Sender = value
					case "receiver":
						dialog.Receiver = value
					case "message":
						dialog.Message = value
					case "timestamp":
						timestamp, err := time.Parse(time.RFC3339, value)
						if err != nil {
							return 0, nil, err
						}
						dialog.Timestamp = timestamp
					}
				}
				dialogs = append(dialogs, dialog)
			}
		}

		return newCursor, dialogs, nil
	}

	return 0, nil, fmt.Errorf("неверный формат результата")
}

func dialogSend(c *gin.Context) {

	var dialog Dialog

	userFrom := c.Param("userId")

	if err := c.BindJSON(&dialog); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	client := redis.NewClient(&redis.Options{
		Addr:     "redis:6379",
		Password: "",
		DB:       0,
	})

	ctx := context.Background()

	dialogTime := time.Now()

	key := fmt.Sprintf("dialog:%s:%s:%d", dialog.Sender, userFrom, dialogTime)

	err := client.HSet(ctx, key, map[string]interface{}{
		"sender":    dialog.Sender,
		"receiver":  userFrom,
		"message":   dialog.Message,
		"timestamp": dialogTime,
	}).Err()
	if err != nil {
		log.Panic(err)
	}

	c.IndentedJSON(http.StatusCreated, gin.H{"Dialog created at": dialogTime})
}

func dialogList(c *gin.Context) {

	userId := c.Param("userId")
	client := redis.NewClient(&redis.Options{
		Addr:     "redis:6379",
		Password: "",
		DB:       0,
	})

	ctx := context.Background()

	pong, err := client.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("Ошибка подключения к Redis: %v", err)
	}
	fmt.Println("Подключение к Redis успешно:", pong)
	cursor := uint64(0) // Начальный курсор
	limit := 10         // Лимит на количество диалогов

	for {
		newCursor, dialogResult, err := FindDialogsByUserRedisFunction(client, userId, cursor, limit)
		if err != nil {
			log.Fatalf("Ошибка при поиске диалогов: %v", err)
		}
		// Если курсор равен 0, завершаем пагинацию
		if newCursor == 0 {
			c.IndentedJSON(http.StatusOK, dialogResult)
			break
		}

		// Обновляем курсор для следующей итерации
		cursor = newCursor
	}

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
