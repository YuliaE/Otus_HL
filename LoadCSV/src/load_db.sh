echo "IP"
hostname -i

echo "Sleeping for 40 seconds…"
sleep 40

echo "Start load CSV"
psql postgresql://user:user@pgmaster:5432/otus_db  -a -f "/src/my_script.sql"

echo "End load CSV"