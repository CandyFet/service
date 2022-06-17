// Package handlers contains the full set of handlers functions
// supproted by the web api

package handlers

import (
	"log"
	"net/http"
	"os"

	"github.com/dimfeld/httptreemux/v5"
)

// API constructs an http.Handler with all application routes
func API(build string, shutdown chan os.Signal, log *log.Logger) *httptreemux.ContextMux {
	tm := httptreemux.NewContextMux()

	check := check{
		log: log,
	}
	tm.Handle(http.MethodGet, "/test", check.readiness)

	return tm
}
