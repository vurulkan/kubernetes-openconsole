package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

type AzureADConfig struct {
	Enabled      bool
	TenantID     string
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

// AzureAuthority is the Entra ID sign-in host. Override it (AZURE_AD_AUTHORITY)
// for sovereign clouds, e.g. https://login.microsoftonline.us (Azure
// Government) or https://login.partner.microsoftonline.cn (Azure China).
var AzureAuthority = "https://login.microsoftonline.com"

func azureIssuer(tenantID string) string {
	return fmt.Sprintf("%s/%s/v2.0", AzureAuthority, tenantID)
}

func azureEndpoint(tenantID string) oauth2.Endpoint {
	base := fmt.Sprintf("%s/%s/oauth2/v2.0", AzureAuthority, tenantID)
	return oauth2.Endpoint{
		AuthURL:  base + "/authorize",
		TokenURL: base + "/token",
	}
}

func AzureAuthorizeURL(ctx context.Context, cfg AzureADConfig, state string) (string, error) {
	_ = ctx
	oauthCfg := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     azureEndpoint(cfg.TenantID),
		RedirectURL:  cfg.RedirectURL,
		Scopes:       []string{"openid", "profile", "email"},
	}
	return oauthCfg.AuthCodeURL(state), nil
}

func AzureExchangeCode(ctx context.Context, cfg AzureADConfig, code string) (string, error) {
	oauthCfg := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     azureEndpoint(cfg.TenantID),
		RedirectURL:  cfg.RedirectURL,
		Scopes:       []string{"openid", "profile", "email"},
	}
	token, err := oauthCfg.Exchange(ctx, code)
	if err != nil {
		return "", err
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return "", fmt.Errorf("missing id_token")
	}
	claims := jwt.MapClaims{}
	parser := jwt.NewParser()
	_, _, err = parser.ParseUnverified(rawIDToken, claims)
	if err != nil {
		return "", err
	}
	issuer, _ := claims["iss"].(string)
	if issuer != azureIssuer(cfg.TenantID) {
		return "", fmt.Errorf("invalid issuer")
	}
	// The token comes straight from the token endpoint over TLS (OIDC Core
	// 3.1.3.7 lets that stand in for the signature check), but it still
	// must not be expired.
	if exp, err := claims.GetExpirationTime(); err != nil || exp == nil || time.Now().After(exp.Time) {
		return "", fmt.Errorf("id_token expired or without exp")
	}
	audience := claims["aud"]
	switch aud := audience.(type) {
	case string:
		if aud != cfg.ClientID {
			return "", fmt.Errorf("invalid audience")
		}
	case []any:
		found := false
		for _, entry := range aud {
			if value, ok := entry.(string); ok && value == cfg.ClientID {
				found = true
				break
			}
		}
		if !found {
			return "", fmt.Errorf("invalid audience")
		}
	case []string:
		found := false
		for _, value := range aud {
			if value == cfg.ClientID {
				found = true
				break
			}
		}
		if !found {
			return "", fmt.Errorf("invalid audience")
		}
	default:
		return "", fmt.Errorf("invalid audience")
	}
	preferredUsername, _ := claims["preferred_username"].(string)
	email, _ := claims["email"].(string)
	upn, _ := claims["upn"].(string)
	username := strings.TrimSpace(preferredUsername)
	if username == "" {
		username = strings.TrimSpace(email)
	}
	if username == "" {
		username = strings.TrimSpace(upn)
	}
	if username == "" {
		return "", fmt.Errorf("no suitable username claim found")
	}
	return username, nil
}

func TestAzureConnection(ctx context.Context, cfg AzureADConfig) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/%s/v2.0/.well-known/openid-configuration", AzureAuthority, cfg.TenantID), nil)
	if err != nil {
		return err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("openid discovery failed with status %d", response.StatusCode)
	}
	return err
}

