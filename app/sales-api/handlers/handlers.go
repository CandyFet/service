// Package handlers contains the full set of handlers functions
// supproted by the web api

package handlers

import (
	"log"
	"net/http"
	"os"

	"github.com/CandyFet/service/business/mid"
	"github.com/CandyFet/service/foundation/web"
)

// API constructs an http.Handler with all application routes
func API(build string, shutdown chan os.Signal, log *log.Logger) *web.App {
	app := web.NewApp(shutdown, mid.Logger(log), mid.Errors(log), mid.Metrics(), mid.Panics(log))

	check := check{
		log: log,
	}
	app.Handle(http.MethodGet, "/readiness", check.readiness)

	return app
}
