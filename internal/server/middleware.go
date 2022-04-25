package grpcserver

// import (
// 	"fmt"
// 	"log"
// 	"net"
// 	"net/http"
// 	"sync"
// 	"time"

// 	"golang.org/x/time/rate"
// )

// // Create a custom request struct which holds the rate limiter for each
// // visitor and the last time that the request was seen.
// type request struct {
// 	limiter  *rate.Limiter
// 	lastSeen time.Time
// }

// // Change the the map to hold values of the type request.
// // defaultTime using 3 minutes
// var requests = make(map[string]*request)
// var mu sync.Mutex

// func getRequest(ip string) *rate.Limiter {
// 	mu.Lock()
// 	defer mu.Unlock()

// 	v, exists := requests[ip]
// 	if !exists {
// 		// TODO: move limit to params
// 		rt := rate.Every(5 * time.Minute / 5)
// 		limiter := rate.NewLimiter(rt, 1)
// 		requests[ip] = &request{limiter, time.Now()}
// 		return limiter
// 	}
// 	// Update the last seen time for the visitor.
// 	v.lastSeen = time.Now()
// 	return v.limiter
// }

// func bruteForceProtectorMiddleware(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		ip, _, err := net.SplitHostPort(r.RemoteAddr)
// 		if err != nil {
// 			log.Println(err.Error())
// 			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
// 			return
// 		}
// 		limiter := getRequest(ip)
// 		fmt.Println(limiter.Allow())
// 		if limiter.Allow() == false {
// 			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
// 			return
// 		}
// 		next.ServeHTTP(w, r)
// 	})
// }
