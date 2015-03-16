BASE_URL="http://localhost:8899/ida/api/v1.0"

curl $BASE_URL/info
curl $BASE_URL/cursor
curl $BASE_URL/cursor?ea=0x89ab
curl $BASE_URL/segments
curl $BASE_URL/segments?ea=0x89ab
curl $BASE_URL/names
curl $BASE_URL/color?ea=0x89ab
curl $BASE_URL/color?ea=0x89ab?color=FF0000
