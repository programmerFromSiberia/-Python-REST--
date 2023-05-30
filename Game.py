from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from datetime import datetime, timedelta
import jwt
from jwt.exceptions import DecodeError, ExpiredSignatureError
from pydantic import BaseModel
from typing import Optional

#Затем мы создадим класс User для хранения данных пользователей. Он будет иметь два атрибута: username и password.

python
class User:
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
#Создадим базу данных пользователей, представленную в виде списка объектов User:

python
users_db = [
    User('user1', 'password1'),
    User('user2', 'password2'),
]
#Теперь мы можем создать экземпляр класса FastAPI и экземпляр класса HTTPBasic для аутентификации пользователей:

python
app = FastAPI()

security = HTTPBasic()
#Мы также создадим модель Token для представления токена доступа к сервису. Она будет содержать два атрибута: access_token и token_type.

python
class Token(BaseModel):
    access_token: str
    token_type: str
#Затем мы создадим функцию generate_token, которая будет генерировать токен. Она принимает имя пользователя (логин) и срок действия токена (в часах). Внутри функции мы создаем словарь payload, который содержит информацию о пользователе и срок действия токена. Затем мы кодируем этот словарь с помощью JWT и возвращаем строковое представление токена.

python
def generate_token(username: str, expires_in: int = 24) -> str:
    payload = {
        'sub': username,
        'exp': datetime.utcnow() + timedelta(hours=expires_in)
    }
    token = jwt.encode(payload, 'secret_key', algorithm='HS256')
    return token.decode('utf-8')
#Обратите внимание на то, что мы используем секретный ключ (secret_key) для кодирования токена. Этот ключ должен храниться в безопасном месте и не должен быть раскрыт никому.

#Теперь мы можем создать функцию validate_token, которая будет проверять валидность токена. Она принимает строку-токен и возвращает имя пользователя (логин), если токен является валидным. Если токен недействителен или срок его действия истек, функция генерирует HTTP-исключение со статусом 401 (Unauthorized).

python
def validate_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, 'secret_key', algorithms=['HS256'])
        username = payload['sub']
        return username
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail='Token has expired')
    except DecodeError:
        raise HTTPException(status_code=401, detail='Invalid token')
#Теперь мы можем создать точку входа в сервис, которая будет проверять аутентификационные данные пользователя и выдавать токен. Мы определим две зависимости: authenticate, которая будет проверять логин и пароль пользователя, и get_current_username, которая будет извлекать имя пользователя из токена.
@app.post('/login', response_model=Token)
async def login(credentials: HTTPBasicCredentials = Depends(security)):
user = authenticate(credentials)
access_token = generate_token(user.username)
return {'access_token': access_token, 'token_type': 'bearer'}

async def get_current_username(credentials: HTTPBasicCredentials = Depends(security)):
token = credentials.credentials
username = validate_token(token)
if not username:
raise HTTPException(status_code=401, detail='Invalid token')
return username


#Функция `authenticate` принимает учетные данные пользователя, проверяет их и возвращает объект User, если они корректны. В нашем случае мы просто сравниваем логин и пароль с хардкодированными значениями.

```python
def authenticate(credentials: HTTPBasicCredentials) -> Optional[User]:
    for user in users_db:
        if user.username == credentials.username and user.password == credentials.password:
            return user
    return None
#Теперь мы можем создать две защищенные точки входа в сервис: /user и /items. Они обе требуют наличия токена в заголовке Authorization. Мы будем использовать зависимость get_current_username, чтобы получить имя пользователя из токена.

python
@app.get('/user')
async def read_user_me(username: str = Depends(get_current_username)):
    return {'username': username}

@app.get('/items')
async def read_items(username: str = Depends(get_current_username)):
    return [{'item_id': 'Item 1'}, {'item_id': 'Item 2'}]
#Наконец, мы можем добавить тесты с использованием Pytest. Мы создадим фикстуру client, которая будет запускать наш сервер, и два теста: один для проверки успешной аутентификации и получения токена, а другой для проверки доступа к защищенным точкам входа.

python
from fastapi.testclient import TestClient

client = TestClient(app)

def test_login():
    response = client.post('/login', headers={'Authorization': 'Basic dXNlcjE6cGFzc3dvcmQx'})
    assert response.status_code == 200
    assert 'access_token' in response.json()

def test_access_protected_resource():
    token = generate_token('user1')
    headers = {'Authorization': f'Bearer {token}'}
    response = client.get('/user', headers=headers)
    assert response.status_code == 200
    assert response.json()['username'] == 'user1'
    response = client.get('/items', headers=headers)
    assert response.status_code == 200
    assert len(response.json()) == 2