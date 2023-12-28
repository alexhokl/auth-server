package api

import (
	"context"
	"net/http"

	"github.com/alexhokl/auth-server/db"
	"github.com/alexhokl/auth-server/store"
	"github.com/gin-gonic/gin"
	"golang.org/x/exp/slog"
)

// CreateClient adds a client
//
//	@Summary		Adds a client
//	@Description	Adds a OAuth client
//	@Tags			clients
//	@Accept			json
//	@Produce		json
//	@Param			body	body	api.ClientCreateRequest	true	"Client details"
//	@Router			/clients/ [post]
func CreateClient(c *gin.Context) {
	var req ClientCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	dbConn, err := db.GetDatabaseConnection()
	if err != nil {
		handleInternalError(c, err, "Unable to connect to database")
		return
	}

	user, err := db.GetUser(dbConn, req.UserEmail)
	if err != nil {
		slog.Error(
			"Error in retrieving user",
			slog.String("email", req.UserEmail),
			slog.String("error", err.Error()),
		)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	if user == nil {
		slog.Error(
			"Unable to find user",
			slog.String("email", req.UserEmail),
		)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	client := store.NewClient(req.ClientID, req.ClientSecret, req.RedirectUri, user.Email, false)

	clientStore := store.NewClientStore(dbConn)
	existingClient, err := clientStore.GetByID(context.TODO(), client.GetID())
	if err != nil {
		slog.Error(
			"Error in retrieving client",
			slog.String("client_id", client.GetID()),
		)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	if existingClient != nil {
		slog.Error(
			"Client already exists",
			slog.String("client_id", client.GetID()),
		)
		c.AbortWithStatusJSON(
			http.StatusBadRequest,
			gin.H{"error": "Client already exists"},
		)
		return
	}

	clientStore.Create(context.TODO(), client)
}

// UpdateClient patches a client
//
//	@Summary		Patches a client
//	@Description	Patches a OAuth client (not implemented yet)
//	@Tags			clients
//	@Accept			json
//	@Produce		json
//	@Router			/clients/ [patch]
func UpdateClient(c *gin.Context) {
	dbConn, err := db.GetDatabaseConnection()
	if err != nil {
		handleInternalError(c, err, "Unable to connect to database")
		return
	}
	client, err := db.GetClient(dbConn, c.Param("client_id"))
	if err != nil {
		slog.Warn(
			"Error in retrieving client",
			slog.String("client_id", c.Param("client_id")),
			slog.String("error", err.Error()),
		)
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	var req ClientUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.ClientSecret != nil {
		client.ClientSecret = *req.ClientSecret
	}
	if req.RedirectUri != nil {
		client.RedirectURI = *req.RedirectUri
	}
	if req.UserEmail != nil {
		client.UserEmail = *req.UserEmail
	}
	if err := db.UpdateClient(dbConn, client); err != nil {
		slog.Error(
			"Error in updating client",
			slog.String("client_id", client.ClientID),
			slog.String("error", err.Error()),
		)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, ClientResponse{
		ClientID:    client.ClientID,
		RedirectUri: client.RedirectURI,
		UserEmail:   client.UserEmail,
	})
}

// ListClients lists clients
//
//	@Summary	Lists clients
//	@Tags		clients
//	@Produce	json
//	@Router		/clients/ [get]
func ListClients(c *gin.Context) {
	dbConn, err := db.GetDatabaseConnection()
	if err != nil {
		handleInternalError(c, err, "Unable to connect to database")
		return
	}

	clients, err := db.GetClients(dbConn)
	if err != nil {
		slog.Error(
			"Unable to list clients",
			slog.String("error", err.Error()),
		)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	clientResponses := make([]ClientResponse, len(clients))
	for i, client := range clients {
		clientResponses[i] = *ToClientResponse(client)
	}

	c.JSON(http.StatusOK, clientResponses)
}
