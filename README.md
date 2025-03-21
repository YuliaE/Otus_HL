# OtusSocialNetwork. Инструкция по запуску

Запрос для создания таблиц лежит в папке `Postgres`.
Коллекция вызовов для Postman лежит в папке `Postman`.

1. Запускаем базу данных и API командой `docker-compose up -d`.
2. Ждем когда контейнеры запустятся
3. Запускаем консоль контейнера Redis `docker exec -it redis bash`
4. В консоли запускаем команду `cat /usr/local/etc/find_dialogs.lua | redis-cli -x FUNCTION LOAD`
В ответе должно быть "dialogs". Если нет "dialogs", то повторить команду 
5. Открываем Postman, создаем новый диалог. Запрос `DialogSend` по адресу `localhost:8080/dialog/ed40b849-fd72-4601-afdb-00d1031beb8c/send` c id пользователя 550e8400-e29b-41d4-a716-446655440000. Данный запрос сохраняет диалог в Redis.
6. Открываем в Postman `DialogList` по адресу `localhost:8080/dialog/ed40b849-fd72-4601-afdb-00d1031beb8c/list` и жмём `Send`. В ответ получим 10 последних диалогов

