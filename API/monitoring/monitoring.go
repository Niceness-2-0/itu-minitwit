package monitoring

import (
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	RequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Duration of HTTP requests.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "route", "status"},
	)

	LoginSuccess = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "login_success_total",
		Help: "Total successful login attempts",
	})

	LoginFailure = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "login_failure_total",
		Help: "Total failed login attempts",
	}, []string{"reason"})

	RegisterSuccess = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "register_success_total",
		Help: "Total successful register attempts",
	})

	MessagesPosted = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "messages_posted_total",
		Help: "Total messages successfully posted",
	})
)

func init() {
	prometheus.MustRegister(RequestDuration)
	prometheus.MustRegister(LoginSuccess)
	prometheus.MustRegister(LoginFailure)
	prometheus.MustRegister(RegisterSuccess)
	prometheus.MustRegister(MessagesPosted)
}

// Middleware to track request timing and status code
type statusRecordingWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *statusRecordingWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func InstrumentHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		rw := &statusRecordingWriter{ResponseWriter: w, statusCode: 200}
		next.ServeHTTP(rw, r)

		duration := time.Since(start).Seconds()
		route := r.URL.Path
		method := r.Method
		status := fmt.Sprintf("%d", rw.statusCode)

		RequestDuration.WithLabelValues(method, route, status).Observe(duration)
	})
}
