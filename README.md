# accounting-ms
## How to run
1. Build flask instance using command `docker build -t web .`
2. Execute docker compose using command `docker-compose up -d`
3. Execute migrations using command `docker-compose exec web flask db upgrade`