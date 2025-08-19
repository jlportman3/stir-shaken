API_USER='alamo-api'
API_PASS='ym@a$A&M7h4Hr&C4'

# Login (Prod)
LOGIN_JSON=$(curl -s -X POST \
  https://authenticate-api.iconectiv.com/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d "{\"userId\":\"$API_USER\",\"password\":\"$API_PASS\"}")

echo $LOGIN_JSON
ACCESS_TOKEN=$(echo "$LOGIN_JSON" | jq -r '.accessToken')
echo "ACCESS_TOKEN=${ACCESS_TOKEN}"
