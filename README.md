# OtusSocialNetwork. Инструкция по запуску

Запрос для создания таблиц лежит в папке `Postgres`.
Коллекция вызовов для Postman лежит в папке `Postman`.

1. Запускаем базу данных и API командой `docker-compose up -d`.
2. Ждем когда Citus запустится, перезагрузится, создадутся таблицы.
3. Запускаем otus_hl_master `docker container start otus_hl_master`
4. Делаем таблицу dialogs шардированной  для чего заходим в консоль контейнера коррдинатора `docker exec -it otus_hl_master psql -U user`. В консоли `SELECT create_distributed_table('dialogs', 'dialog_id');` 
5. Проверяем запущенные ноды `SELECT master_get_active_worker_nodes();`. Если есть otus_hl_worker1, otus_hl_worker2 - всё хорошо, иначе `docker-compose down` и заново запускаем пункт 1 и далее
6. Открываем Postman, создаем новый пост. Запрос `DialogSend` localhost:8080/dialog/ed40b849-fd72-4601-afdb-00d1031beb9c/send
7. Создаём запрос в Postman `DialogList`c userID из пункта 6. localhost:8080/dialog/ed40b849-fd72-4601-afdb-00d1031beb9c/list. Получаем ответ c диалогами

8. Для ребалансировки без остановки можно применить SELECT citus_rebalance_start(); 
Starting in version 11.0, Citus Community edition now supports non-blocking reads and writes during rebalancing.
