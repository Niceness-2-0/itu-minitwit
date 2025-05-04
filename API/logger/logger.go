package logger

import (
	"os"

	"github.com/sirupsen/logrus"
)

func InitLogger() {
	logFilePath := "/var/log/myapp/app.log"
	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		logrus.Warnf("Failed to open log file (%s), using stdout: %v", logFilePath, err)
		logrus.SetOutput(os.Stdout)
	} else {
		logrus.SetOutput(logFile)
	}

	logrus.SetOutput(logFile)
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetLevel(logrus.InfoLevel) // Adjust as needed

	logrus.Info("Logger initialized")
}
