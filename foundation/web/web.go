// Package web contains a small web framework extension.
package web

import (
	"context"
	"net/http"
	"os"
	"syscall"

	"github.com/dimfeld/httptreemux/v5"
)

// Handler is a type thet handles an http request within our own little mini
// framework.
type Handler func(ctx context.Context, w http.ResponseWriter, r *http.Request) error

// App is entrypoint into our application and what configures our context
// ibject for each of our http handlers. Feel free to add any configuration
// data/logic on this App struct
type App struct {
	*httptreemux.ContextMux
	shutdown chan os.Signal
}

// NewApp creates an App value taht handle a set of routes for the application.
func NewApp(shutdown chan os.Signal) *App {
	app := App{
		ContextMux: httptreemux.NewContextMux(),
		shutdown:   shutdown,
	}

	return &app
}

// Handle is our mechanism for mounting Handlers for given HTTP verb and path
// pair, this makes for really easy, convenient routing.
func (a *App) Handle(method string, path string, handler Handler) {

	h := func(w http.ResponseWriter, r *http.Request) {
		if err := handler(r.Context(), w, r); err != nil {
			a.SignalShutdown()
			return
		}
	}

	a.ContextMux.Handle(method, path, h)
}

// SignalShutdown is used to gracefully shutdown the app when an integrity
// issue is identified.
func (a *App) SignalShutdown() {
	a.shutdown <- syscall.SIGTERM
}
