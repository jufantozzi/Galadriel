package main

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	s := echo.New()

	mAuthConfig := middleware.KeyAuthWithConfig(middleware.KeyAuthConfig{
		// onboard route validates through a specific, single-use token
		Skipper:   func(c echo.Context) bool { return c.Path() == "/onboard" },
		Validator: func(key string, c echo.Context) (bool, error) { return e.validateToken(c, key) },
		KeyLookup: "header:Authorization",
	})

	s.Use(mAuthConfig)
}
