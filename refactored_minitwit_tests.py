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
        self.assertIn('You were successfully registered and can login now', decode_data(r))

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
        register('user1', 'default')
        r = login('user1', 'default')
        # self.assertIn('You were logged in', decode_data(r))
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
        login('foo', 'default')
        add_message('test message 1')
        add_message('<test message 2>')

        r = http_session.get(f'{BASE_URL}/')
        self.assertIn('test message 1', decode_data(r))
        self.assertIn('&lt;test message 2&gt;', decode_data(r))  # Ensure HTML escape

    def test_timelines(self):
        """Ensure timelines work correctly"""
        login('foo', 'default')
        add_message('the message by foo')
        logout()

        login('bar', 'default')
        add_message('the message by bar')

        # Public timeline should show both messages
        r = http_session.get(f'{BASE_URL}/public')
        self.assertIn('the message by foo', decode_data(r))
        self.assertIn('the message by bar', decode_data(r))

        # Bar's personal timeline should only show bar's messages
        r = http_session.get(f'{BASE_URL}/')
        self.assertNotIn('the message by foo', decode_data(r))
        self.assertIn('the message by bar', decode_data(r))

        # Follow foo
        r = http_session.get(f'{BASE_URL}/foo/follow', allow_redirects=True)
        self.assertIn('You are now following "foo"', decode_data(r))

        # Timeline should now show foo's messages
        r = http_session.get(f'{BASE_URL}/')
        self.assertIn('the message by foo', decode_data(r))
        self.assertIn('the message by bar', decode_data(r))

        # Bar's user page should only show their messages
        r = http_session.get(f'{BASE_URL}/bar')
        self.assertNotIn('the message by foo', decode_data(r))
        self.assertIn('the message by bar', decode_data(r))

        # Foo's user page should only show their messages
        r = http_session.get(f'{BASE_URL}/foo')
        self.assertIn('the message by foo', decode_data(r))
        self.assertNotIn('the message by bar', decode_data(r))

        # Unfollow foo and check timeline again
        r = http_session.get(f'{BASE_URL}/foo/unfollow', allow_redirects=True)
        self.assertIn('You are no longer following "foo"', decode_data(r))

        r = http_session.get(f'{BASE_URL}/')
        self.assertNotIn('the message by foo', decode_data(r))
        self.assertIn('the message by bar', decode_data(r))


if __name__ == '__main__':
    unittest.main()