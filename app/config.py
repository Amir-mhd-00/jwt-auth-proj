import redis

ALGORITHM = "HS256"

REDIS_HOST = "localhost"
REDIS_PORT = 6379
REDIS_DB = 0

DB_CONFIG = {
    "host": "localhost",
    "database": "usersdb",
    "user": "postgres",
    "password": "password"
}

redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)
