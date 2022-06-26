// Package handlers contains the full set of handlers functions
// supproted by the web api

package handlers

import (
	"log"
	"net/http"
	"os"

	"github.com/CandyFet/service/business/auth"
	"github.com/CandyFet/service/business/mid"
	"github.com/CandyFet/service/foundation/web"
	"github.com/jmoiron/sqlx"
)

// API constructs an http.Handler with all application routes
func API(build string, shutdown chan os.Signal, log *log.Logger, a *auth.Auth, db *sqlx.DB) *web.App {
	app := web.NewApp(shutdown, mid.Logger(log), mid.Errors(log), mid.Metrics(), mid.Panics(log))

	cg := checkGroup{
		build: build,
		db:    db,
	}
	app.Handle(http.MethodGet, "/readiness", cg.readiness)
	app.Handle(http.MethodGet, "/liveness", cg.liveness)

	return app
}
