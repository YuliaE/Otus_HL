package main

import (
	"bytes"
	"context"
	"io"

	// add this
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
)

type newDialog struct {
	Receiver string `json:"userto"`
	Message  string `json:"dialogtext"`
}

type Dialog struct {
	Sender    string `json:"userfrom"`
	Receiver  string `json:"userto"`
	Message   string `json:"dialogtext"`
	Timestamp time.Time
}

func main() {

	router := gin.Default()
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

	router.POST("/dialognew/send", dialogSend)
	router.GET("/dialognew/:userId/list", dialogList)

	router.Run(":3001")

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

	//userFrom := c.Param("userId")

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

	key := fmt.Sprintf("dialog:%s:%s:%d", dialog.Sender, dialog.Receiver, dialogTime)

	err := client.HSet(ctx, key, map[string]interface{}{
		"sender":    dialog.Sender,
		"receiver":  dialog.Receiver,
		"message":   dialog.Message,
		"timestamp": dialogTime,
	}).Err()
	if err != nil {
		log.Panic(err)
	}

	c.IndentedJSON(http.StatusCreated, gin.H{"dialogtime": dialogTime})
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
