package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/netbirdio/netbird/management/server/telemetry"
	"golang.org/x/oauth2"
)

// DexManager represents a Dex provider for Netbird.
type DexManager struct {
	client      *oauth2.Config
	httpClient  ManagerHTTPClient
	credentials *DexCredentials
	helper      ManagerHelper
	appMetrics  telemetry.AppMetrics
}

// DexClientConfig contains the configuration for the Dex provider.
type DexClientConfig struct {
	ClientID      string
	ClientSecret  string
	Issuer        string
	TokenEndpoint string
}

// DexCredentials contains the Dex authentication information.
type DexCredentials struct {
	clientConfig DexClientConfig
	helper       ManagerHelper
	httpClient   ManagerHTTPClient
	appMetrics   telemetry.AppMetrics
}

// NewDexManager creates a new instance of the Dex provider.
func NewDexManager(config DexClientConfig, appMetrics telemetry.AppMetrics) (*DexManager, error) {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.MaxIdleConns = 5

	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: httpTransport,
	}

	helper := JsonParser{}
	config.Issuer = baseURL(config.Issuer)

	if config.ClientID == "" {
		return nil, fmt.Errorf("dex IdP configuration is incomplete, ClientID is missing")
	}

	if config.ClientSecret == "" {
		return nil, fmt.Errorf("dex IdP configuration is incomplete, ClientSecret is missing")
	}

	if config.Issuer == "" {
		return nil, fmt.Errorf("dex IdP configuration is incomplete, Issuer is missing")
	}

	if config.TokenEndpoint == "" {
		return nil, fmt.Errorf("dex IdP configuration is incomplete, TokenEndpoint is missing")
	}

	client := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: config.TokenEndpoint,
		},
		Scopes: []string{"openid", "email", "profile"},
	}

	credentials := &DexCredentials{
		clientConfig: config,
		httpClient:   httpClient,
		helper:       helper,
		appMetrics:   appMetrics,
	}

	return &DexManager{
		client:      client,
		httpClient:  httpClient,
		credentials: credentials,
		helper:      helper,
		appMetrics:  appMetrics,
	}, nil
}

// authenticatedRequest выполняет запрос с аутентификацией
func (dm *DexManager) authenticatedRequest(ctx context.Context, method, endpoint string, body io.Reader) (*http.Response, error) {
	token, err := dm.Authenticate(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("%s %s", token.TokenType, token.AccessToken))

	return dm.httpClient.Do(req)
}

// Authenticate retrieves access token to use the dex user API.
func (dm *DexManager) Authenticate(ctx context.Context) (JWTToken, error) {
	data := url.Values{}
	data.Set("client_id", dm.credentials.clientConfig.ClientID)
	data.Set("client_secret", dm.credentials.clientConfig.ClientSecret)
	data.Set("scope", "openid email profile")

	req, err := http.NewRequestWithContext(ctx, "POST", dm.credentials.clientConfig.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return JWTToken{}, fmt.Errorf("failed to create token request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := dm.httpClient.Do(req)
	if err != nil {
		return JWTToken{}, fmt.Errorf("failed to execute token request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return JWTToken{}, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return JWTToken{}, fmt.Errorf("failed to decode token response: %v", err)
	}

	if tokenResponse.AccessToken == "" {
		return JWTToken{}, fmt.Errorf("received empty access token")
	}

	return JWTToken{
		AccessToken: tokenResponse.AccessToken,
		TokenType:   tokenResponse.TokenType,
		ExpiresIn:   tokenResponse.ExpiresIn,
	}, nil
}

// GetUserDataByID requests user data from Dex via ID.
func (dm *DexManager) GetUserDataByID(ctx context.Context, userID string, appMetadata AppMetadata) (*UserData, error) {
	endpoint := fmt.Sprintf("%s/api/v1/users/%s", dm.credentials.clientConfig.Issuer, userID)

	resp, err := dm.authenticatedRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if dm.appMetrics != nil {
		dm.appMetrics.IDPMetrics().CountGetUserDataByID()
	}

	if resp.StatusCode != http.StatusOK {
		if dm.appMetrics != nil {
			dm.appMetrics.IDPMetrics().CountRequestStatusError()
		}
		return nil, fmt.Errorf("unable to get user %s, statusCode %d", userID, resp.StatusCode)
	}

	var dexUser map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&dexUser); err != nil {
		return nil, fmt.Errorf("failed to decode user data: %v", err)
	}

	userData, err := dm.parseDexUser(dexUser)
	if err != nil {
		return nil, err
	}

	userData.AppMetadata = appMetadata
	return userData, nil
}

// GetUserByEmail searches users with a given email in Dex.
func (dm *DexManager) GetUserByEmail(ctx context.Context, email string) ([]*UserData, error) {
	endpoint := fmt.Sprintf("%s/api/v1/users?email=%s", dm.credentials.clientConfig.Issuer, url.QueryEscape(email))

	resp, err := dm.authenticatedRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if dm.appMetrics != nil {
		dm.appMetrics.IDPMetrics().CountGetUserByEmail()
	}

	if resp.StatusCode != http.StatusOK {
		if dm.appMetrics != nil {
			dm.appMetrics.IDPMetrics().CountRequestStatusError()
		}
		return nil, fmt.Errorf("unable to get user %s, statusCode %d", email, resp.StatusCode)
	}

	var dexUser map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&dexUser); err != nil {
		return nil, fmt.Errorf("failed to decode user data: %v", err)
	}

	userData, err := dm.parseDexUser(dexUser)
	if err != nil {
		return nil, err
	}

	return []*UserData{userData}, nil
}

// GetAccount returns all the users for a given profile in Dex.
func (dm *DexManager) GetAccount(ctx context.Context, accountID string) ([]*UserData, error) {
	users, err := dm.getAllUsers(ctx)
	if err != nil {
		return nil, err
	}

	if dm.appMetrics != nil {
		dm.appMetrics.IDPMetrics().CountGetAccount()
	}

	for index, user := range users {
		user.AppMetadata.WTAccountID = accountID
		users[index] = user
	}

	return users, nil
}

// GetAllAccounts gets all registered accounts with corresponding user data from Dex.
func (dm *DexManager) GetAllAccounts(ctx context.Context) (map[string][]*UserData, error) {
	users, err := dm.getAllUsers(ctx)
	if err != nil {
		return nil, err
	}

	indexedUsers := make(map[string][]*UserData)
	indexedUsers[UnsetAccountID] = append(indexedUsers[UnsetAccountID], users...)

	if dm.appMetrics != nil {
		dm.appMetrics.IDPMetrics().CountGetAllAccounts()
	}

	return indexedUsers, nil
}

// getAllUsers returns all users in a Dex instance.
func (dm *DexManager) getAllUsers(ctx context.Context) ([]*UserData, error) {
	endpoint := fmt.Sprintf("%s/api/v1/users", dm.credentials.clientConfig.Issuer)

	resp, err := dm.authenticatedRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if dm.appMetrics != nil {
			dm.appMetrics.IDPMetrics().CountRequestStatusError()
		}
		return nil, fmt.Errorf("unable to get all users, statusCode %d", resp.StatusCode)
	}

	var dexUsers []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&dexUsers); err != nil {
		return nil, fmt.Errorf("failed to decode users: %v", err)
	}

	users := make([]*UserData, 0, len(dexUsers))
	for _, dexUser := range dexUsers {
		userData, err := dm.parseDexUser(dexUser)
		if err != nil {
			return nil, err
		}
		users = append(users, userData)
	}

	return users, nil
}

// parseDexUser parses Dex user data into UserData struct.
func (dm *DexManager) parseDexUser(dexUser map[string]interface{}) (*UserData, error) {
	email, _ := dexUser["email"].(string)
	id, _ := dexUser["sub"].(string)
	name, _ := dexUser["name"].(string)

	if email == "" || id == "" {
		return nil, fmt.Errorf("invalid dex user: missing required fields")
	}

	if name == "" {
		name = email
	}

	return &UserData{
		Email: email,
		Name:  name,
		ID:    id,
	}, nil
}

// CreateUser creates a new user in Dex IdP and sends an invitation.
func (dm *DexManager) CreateUser(ctx context.Context, email, firstName, lastName, password string) (*UserData, error) {
	return nil, fmt.Errorf("method CreateUser not implemented")
}

// UpdateUserAppMetadata updates user app metadata in Dex.
func (dm *DexManager) UpdateUserAppMetadata(ctx context.Context, userID string, appMetadata AppMetadata) error {
	return fmt.Errorf("method UpdateUserAppMetadata not implemented")
}

// DeleteUser deletes a user from Dex.
func (dm *DexManager) DeleteUser(ctx context.Context, userID string) error {
	endpoint := fmt.Sprintf("%s/api/v1/users/%s", dm.credentials.clientConfig.Issuer, userID)

	resp, err := dm.authenticatedRequest(ctx, "DELETE", endpoint, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if dm.appMetrics != nil {
		dm.appMetrics.IDPMetrics().CountDeleteUser()
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		if dm.appMetrics != nil {
			dm.appMetrics.IDPMetrics().CountRequestStatusError()
		}
		return fmt.Errorf("unable to delete user, statusCode %d", resp.StatusCode)
	}

	return nil
}

// InviteUserByID resend invitations to users who haven't activated,
// their accounts prior to the expiration period.
func (dm *DexManager) InviteUserByID(_ context.Context, _ string) error {
	return fmt.Errorf("method InviteUserByID not implemented")
}
