import os
import json
import base64
import sqlite3
import requests
from pathlib import Path
from contextlib import closing
import psycopg2
from psycopg2 import sql
from dotenv import load_dotenv

env_path = Path(__file__).resolve().parent.parent / '.env'
load_dotenv(dotenv_path=env_path)

DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", 5432)

BASE_URL = os.getenv('TEST_IP', 'http://127.0.0.1:5001')
USERNAME = os.getenv("TEST_USERNAME")
PWD = os.getenv("TEST_PWD")
CREDENTIALS = ':'.join([USERNAME, PWD]).encode('ascii')
ENCODED_CREDENTIALS = base64.b64encode(CREDENTIALS).decode()
HEADERS = {'Connection': 'close',
           'Content-Type': 'application/json',
           f'Authorization': f'Basic {ENCODED_CREDENTIALS}'}

def init_db():
    with psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=DB_PORT
    ) as conn:
        conn.autocommit = True
        with conn.cursor() as cursor:
            # Optional: Drop all tables first
            cursor.execute("""
                DO $$ DECLARE
                    r RECORD;
                BEGIN
                    -- disable referential integrity
                    EXECUTE 'DROP SCHEMA public CASCADE';
                    EXECUTE 'CREATE SCHEMA public';
                END $$;
            """)

            # Then run schema.sql
            schema_path = Path(__file__).resolve().parent.parent / 'database' / 'schema.sql'
            with open(schema_path, 'r') as f:
                cursor.execute(f.read())
init_db()

def test_latest():
    # post something to update LATEST
    url = f"{BASE_URL}/register"
    data = {'username': 'test', 'email': 'test@test', 'pwd': 'foo'}
    params = {'latest': 1337}
    response = requests.post(url, data=json.dumps(data),
                             params=params, headers=HEADERS)
    assert response.ok

    # verify that latest was updated
    url = f'{BASE_URL}/latest'
    response = requests.get(url, headers=HEADERS)
    assert response.ok
    assert response.json()['latest'] == 1337


def test_register():
    username = 'a'
    email = 'a@a.a'
    pwd = 'a'
    data = {'username': username, 'email': email, 'pwd': pwd}
    params = {'latest': 1}
    response = requests.post(f'{BASE_URL}/register',
                             data=json.dumps(data), headers=HEADERS, params=params)
    assert response.ok
    # TODO: add another assertion that it is really there

    # verify that latest was updated
    response = requests.get(f'{BASE_URL}/latest', headers=HEADERS)
    assert response.json()['latest'] == 1


def test_create_msg():
    username = 'a'
    data = {'content': 'Blub!'}
    url = f'{BASE_URL}/msgs/{username}'
    params = {'latest': 2}
    response = requests.post(url, data=json.dumps(data),
                             headers=HEADERS, params=params)
    assert response.ok

    # verify that latest was updated
    response = requests.get(f'{BASE_URL}/latest', headers=HEADERS)
    assert response.json()['latest'] == 2


def test_get_latest_user_msgs():
    username = 'a'

    query = {'no': 20, 'latest': 3}
    url = f'{BASE_URL}/msgs/{username}'
    response = requests.get(url, headers=HEADERS, params=query)
    assert response.status_code == 200

    got_it_earlier = False
    for msg in response.json():
        if msg['content'] == 'Blub!' and msg['user'] == username:
            got_it_earlier = True

    assert got_it_earlier

    # verify that latest was updated
    response = requests.get(f'{BASE_URL}/latest', headers=HEADERS)
    assert response.json()['latest'] == 3


def test_get_latest_msgs():
    username = 'a'
    query = {'no': 20, 'latest': 4}
    url = f'{BASE_URL}/msgs'
    response = requests.get(url, headers=HEADERS, params=query)
    assert response.status_code == 200

    got_it_earlier = False
    for msg in response.json():
        if msg['content'] == 'Blub!' and msg['user'] == username:
            got_it_earlier = True

    assert got_it_earlier

    # verify that latest was updated
    response = requests.get(f'{BASE_URL}/latest', headers=HEADERS)
    assert response.json()['latest'] == 4


def test_register_b():
    username = 'b'
    email = 'b@b.b'
    pwd = 'b'
    data = {'username': username, 'email': email, 'pwd': pwd}
    params = {'latest': 5}
    response = requests.post(f'{BASE_URL}/register', data=json.dumps(data),
                             headers=HEADERS, params=params)
    assert response.ok
    # TODO: add another assertion that it is really there

    # verify that latest was updated
    response = requests.get(f'{BASE_URL}/latest', headers=HEADERS)
    assert response.json()['latest'] == 5


def test_register_c():
    username = 'c'
    email = 'c@c.c'
    pwd = 'c'
    data = {'username': username, 'email': email, 'pwd': pwd}
    params = {'latest': 6}
    response = requests.post(f'{BASE_URL}/register', data=json.dumps(data),
                             headers=HEADERS, params=params)
    assert response.ok

    # verify that latest was updated
    response = requests.get(f'{BASE_URL}/latest', headers=HEADERS)
    assert response.json()['latest'] == 6


def test_follow_user():
    username = 'a'
    url = f'{BASE_URL}/fllws/{username}'
    data = {'follow': 'b'}
    params = {'latest': 7}
    response = requests.post(url, data=json.dumps(data),
                             headers=HEADERS, params=params)
    assert response.ok

    data = {'follow': 'c'}
    params = {'latest': 8}
    response = requests.post(url, data=json.dumps(data),
                             headers=HEADERS, params=params)
    assert response.ok

    query = {'no': 20, 'latest': 9}
    response = requests.get(url, headers=HEADERS, params=query)
    assert response.ok

    json_data = response.json()
    assert "b" in json_data["follows"]
    assert "c" in json_data["follows"]

    # verify that latest was updated
    response = requests.get(f'{BASE_URL}/latest', headers=HEADERS)
    assert response.json()['latest'] == 9


def test_a_unfollows_b():
    username = 'a'
    url = f'{BASE_URL}/fllws/{username}'

    #  first send unfollow command
    data = {'unfollow': 'b'}
    params = {'latest': 10}
    response = requests.post(url, data=json.dumps(data),
                             headers=HEADERS, params=params)
    assert response.ok

    # then verify that b is no longer in follows list
    query = {'no': 20, 'latest': 11}
    response = requests.get(url, params=query, headers=HEADERS)
    assert response.ok
    assert 'b' not in response.json()['follows']

    # verify that latest was updated
    response = requests.get(f'{BASE_URL}/latest', headers=HEADERS)
    assert response.json()['latest'] == 11

