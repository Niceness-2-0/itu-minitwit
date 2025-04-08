# ITU-MiniTwit GO Project

ITU-MiniTwit API built with Go using Gorilla Mux. This project provides user authentication, registration, and basic posting functionality.

## 🚀 Features

- User Registration and Authentication
- RESTful API Endpoints

## 🛠️ Installation

1. **Install dependencies**

   ```sh
   go mod tidy
   ```

2. **Run the project**
   ```sh
   go run main.go
   ```

## 🧪 Running Tests

To run the test suite (`main_test.go`), use:

```sh
go test ./...
```

## 📚 API Endpoints

| Method | Endpoint               | Description                                                                                                                                                                      |
| ------ | ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/public`              | Displays the latest messages of all users                                                                                                                                        |
| POST   | `/login`               | Logs the user in                                                                                                                                                                 |
| POST   | `/register`            | Registers the user                                                                                                                                                               |
| GET    | `/logout`              | Logs the user out                                                                                                                                                                |
| GET    | `/`                    | Shows a users timeline or if no user is logged in it will redirect to the public timeline. This timeline shows the user's messages as well as all the messages of followed users |
| GET    | `/{username}`          | Display's a users tweets                                                                                                                                                         |
| POST   | `/{username}/follow`   | Adds the current user as follower of the given user                                                                                                                              |
| POST   | `/{username}/unfollow` | Removes the current user as follower of the given user                                                                                                                           |
| POST   | `/add_message`         | Registers a new message for the user                                                                                                                                             |

## 📜 License

---
