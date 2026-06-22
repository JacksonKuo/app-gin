package main

import (
  "log"
  "net/http"
  "os"

  "github.com/gin-gonic/gin"
)

func main() {
  // Create a Gin router with default middleware (logger and recovery)
  r := gin.Default()

  // Define a simple GET endpoint
  r.GET("/ping", func(c *gin.Context) {
    // Return JSON response
    c.JSON(http.StatusOK, gin.H{
      "message": "pong",
    })
  })

  // Temporary: prove the Okta env injection works. Issuer is a public URL
  // (non-sensitive), so it's safe to echo. Remove once OIDC is wired up.
  r.GET("/env", func(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{
      "OKTA_OAUTH2_ISSUER": os.Getenv("OKTA_OAUTH2_ISSUER"),
      "OKTA_REDIRECT_URI":  os.Getenv("OKTA_REDIRECT_URI"),
    })
  })

  // Serve HTTPS with the Let's Encrypt cert when it's mounted (prod/K3s),
  // otherwise fall back to plain HTTP (local dev). Go reads the PEM files
  // directly, so no keystore conversion is needed.
  certFile := "/etc/letsencrypt/live/bakacore.com/fullchain.pem"
  keyFile := "/etc/letsencrypt/live/bakacore.com/privkey.pem"

  var err error
  if _, statErr := os.Stat(certFile); statErr == nil {
    log.Println("TLS cert found; serving HTTPS on :2096")
    err = r.RunTLS(":2096", certFile, keyFile)
  } else {
    log.Println("no TLS cert; serving HTTP on :2096")
    err = r.Run(":2096")
  }
  if err != nil {
    log.Fatalf("failed to run server: %v", err)
  }
}