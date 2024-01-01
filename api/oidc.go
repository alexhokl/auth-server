package api

import (
	"net/http"

	"github.com/alexhokl/auth-server/db"
	"github.com/gin-gonic/gin"
)

func ListOIDCCLients(c *gin.Context) {
	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	clients, err := db.ListOIDCClients(dbConn)
	if err != nil {
		handleInternalError(c, err, "Failed to list OIDC clients")
		return
	}

	if len(clients) == 0 {
		c.JSON(http.StatusOK, []OIDCClientResponse{})
		return
	}

	var viewModels []OIDCClientResponse
	for _, c := range clients {
		viewModels = append(viewModels, OIDCClientResponse{
			Name:        c.Name,
			ClientID:    c.ClientID,
			RedirectURI: c.RedirectURI,
			ButtonName:  c.ButtonName,
		})
	}

	c.JSON(http.StatusOK, viewModels)
}

func CreateOIDCClient(c *gin.Context) {
	var request OIDCClientCreateRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		handleBadRequest(c, err, "Failed to parse request body")
		return
	}

	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	client := db.OidcClient{
		Name:        request.Name,
		ClientID:    request.ClientID,
		ClientSecret: request.ClientSecret,
		RedirectURI: request.RedirectURI,
		ButtonName:  request.ButtonName,
	}

	if err := db.CreateOIDCClient(dbConn, &client); err != nil {
		handleInternalError(c, err, "Failed to create OIDC client")
		return
	}

	c.JSON(http.StatusCreated, OIDCClientResponse{
		Name:        client.Name,
		ClientID:    client.ClientID,
		RedirectURI: client.RedirectURI,
		ButtonName:  client.ButtonName,
	})
}

func UpdateOIDCClient(c *gin.Context) {
	var request OIDCClientUpdateRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		handleBadRequest(c, err, "Failed to parse request body")
		return
	}

	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	client := &db.OidcClient{
		Name:        c.Param("name"),
		ClientID:    request.ClientID,
		ClientSecret: request.ClientSecret,
		RedirectURI: request.RedirectURI,
		ButtonName:  request.ButtonName,
	}

	if err := db.UpdateOIDCClient(dbConn, client); err != nil {
		handleInternalError(c, err, "Failed to update OIDC client")
		return
	}

	c.JSON(http.StatusOK, OIDCClientResponse{
		Name:        client.Name,
		ClientID:    client.ClientID,
		RedirectURI: client.RedirectURI,
		ButtonName:  client.ButtonName,
	})
}

func DeleteOIDCClient(c *gin.Context) {
	name := c.Param("name")

	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	if err := db.DeleteOIDCClient(dbConn, name); err != nil {
		handleInternalError(c, err, "Failed to delete OIDC client")
		return
	}

	c.Status(http.StatusOK)
}
