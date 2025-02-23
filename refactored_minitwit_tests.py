# -*- coding: utf-8 -*-
"""
    MiniTwit Tests
    ~~~~~~~~~~~~~~

    Tests the MiniTwit application (GO version).

    :copyright: (c) 2010 by Armin Ronacher.
    :license: BSD, see LICENSE for more details.
"""
import requests
import unittest
import html

# BASE_URL to the Go application
BASE_URL = "http://localhost:5010"

# Session persistence for authentication
http_session = requests.Session()

def decode_data(response):
    """Helper function to decode in utf-8 the response data"""
    return response.text

def register(username, password, password2=None, email=None):
    """Helper function to register a user"""
    if password2 is None:
        password2 = password
    if email is None:
        email = username + '@example.com'

    return http_session.post(f'{BASE_URL}/register', data={
        'username': username,
        'password': password,
        'password2': password2,
        'email': email,
    }, allow_redirects=True)

def login(username, password):
    """Helper function to login"""
    r = http_session.post(f'{BASE_URL}/login', data={
        'username': username,
        'password': password
    }, allow_redirects=True)
    return r

    '''
    def register_and_login(self, username, password):
        """Registers and logs in in one go"""
        self.register(username, password)
        return self.login(username, password)
    '''
def logout():
    """Helper function to logout"""
    return http_session.get(f'{BASE_URL}/logout', allow_redirects=True)

def add_message(text):
    """Adds a message"""
    r = http_session.post(f'{BASE_URL}/add_message', data={'text': text}, allow_redirects=True)
    return r

    # testing functions

class MiniTwitGoTestCase(unittest.TestCase):

    def test_register(self):
        """Ensure registration works"""
        r = register('user1', 'default')
        self.assertIn('The username is already taken', decode_data(r))

        r = register('', 'default')
        self.assertIn('You have to enter a username', decode_data(r))

        r = register('meh', '')
        self.assertIn('You have to enter a password', decode_data(r))

        r = register('meh', 'x', 'y')
        self.assertIn('The two passwords do not match', decode_data(r))

        r = register('meh', 'foo', email='broken')
        self.assertIn('You have to enter a valid email address', decode_data(r))

    def test_login_logout(self):
        """Ensure login and logout work correctly"""
        r = register('user1', 'default')
        self.assertIn('You were successfully registered and can login now', decode_data(r))
        r = login('user1', 'default')
        self.assertEqual(r.status_code, 200)

        # Check timeline for the flash message
        self.assertIn('You were logged in', decode_data(r)) 

        # Logout
        r = logout()
        self.assertIn('You were logged out', decode_data(r))

        r = login('user1', 'wrongpassword')
        self.assertIn('Invalid password', decode_data(r))

        r = login('user2', 'wrongpassword')
        self.assertIn('Invalid username', decode_data(r))

    def test_message_recording(self):
        """Ensure message posting works"""
        login('user1', 'default')
        r = add_message('test message 1')
        self.assertIn('test message 1', decode_data(r))

        r = add_message('<test message 2>')
        self.assertIn(html.escape('<test message 2>'), decode_data(r))

    def test_timelines(self):
        """Ensure timelines work correctly"""
        login('user1', 'default')
        add_message('the message by user1')
        logout()

        login('Joki', 'idk')
        add_message('the message by Joki')

        # Public timeline should show both messages
        r = http_session.get(f'{BASE_URL}/public')
        self.assertIn('the message by user1', decode_data(r))
        self.assertIn('the message by Joki', decode_data(r))

        # Joki's personal timeline should only show bar's messages
        r = http_session.get(f'{BASE_URL}/')
        self.assertNotIn('the message by user1', decode_data(r))
        self.assertIn('the message by Joki', decode_data(r))

        # Follow user1
        r = http_session.get(f'{BASE_URL}/user1/follow', allow_redirects=True)
        self.assertIn('You are now following "user1"', html.unescape(decode_data(r)))

        # Timeline should now show user1's messages
        r = http_session.get(f'{BASE_URL}/')
        self.assertIn('the message by user1', decode_data(r))
        self.assertIn('the message by Joki', decode_data(r))

        # Joki's user page should only show their messages
        r = http_session.get(f'{BASE_URL}/Joki')
        self.assertNotIn('the message by user1', decode_data(r))
        self.assertIn('the message by Joki', decode_data(r))

        # user1's user page should only show their messages
        r = http_session.get(f'{BASE_URL}/user1')
        self.assertIn('the message by user1', decode_data(r))
        self.assertNotIn('the message by Joki', decode_data(r))

        # Unfollow user1 and check timeline again
        r = http_session.get(f'{BASE_URL}/user1/unfollow', allow_redirects=True)
        self.assertIn('You are no longer following "user1"', html.unescape(decode_data(r)))

        r = http_session.get(f'{BASE_URL}/')
        self.assertNotIn('the message by user1', decode_data(r))
        self.assertIn('the message by Joki', decode_data(r))


        # A clean-up function would be required to delete 'user1' from the DB and the last 4 messages


if __name__ == '__main__':
    unittest.main()