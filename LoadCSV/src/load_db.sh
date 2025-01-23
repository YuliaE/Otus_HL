echo "IP"
hostname -i

echo "Sleeping for 40 seconds…"
sleep 40

echo "Start load CSV"
psql postgresql://user:user@otus_hl_master:5432/user  -a -f "/src/my_script.sql"

echo "End load CSV"