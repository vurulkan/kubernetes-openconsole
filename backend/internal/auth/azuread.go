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
	// Authority is the Entra ID sign-in host; empty = DefaultAzureAuthority.
	Authority string
}

// DefaultAzureAuthority is the Entra ID sign-in host. AZURE_AD_AUTHORITY overrides it
// for sovereign clouds, e.g. https://login.microsoftonline.us (Azure
// Government) or https://login.partner.microsoftonline.cn (Azure China).
const DefaultAzureAuthority = "https://login.microsoftonline.com"

func (c AzureADConfig) authority() string {
	if c.Authority == "" {
		return DefaultAzureAuthority
	}
	return strings.TrimRight(c.Authority, "/")
}

func azureIssuer(cfg AzureADConfig) string {
	return fmt.Sprintf("%s/%s/v2.0", cfg.authority(), cfg.TenantID)
}

func azureEndpoint(cfg AzureADConfig) oauth2.Endpoint {
	base := fmt.Sprintf("%s/%s/oauth2/v2.0", cfg.authority(), cfg.TenantID)
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
		Endpoint:     azureEndpoint(cfg),
		RedirectURL:  cfg.RedirectURL,
		Scopes:       []string{"openid", "profile", "email"},
	}
	return oauthCfg.AuthCodeURL(state), nil
}

// AzureIdentity is who signed in: Username is the account name
// (preferred_username, else email, else upn); Email and UPN are the raw
// claims, used to find an account an admin pre-created under another name.
type AzureIdentity struct {
	Username string
	Email    string
	UPN      string
	OID      string // Entra object id: the same person across renames
	// AMR: how the person signed in ("pwd", "mfa", …); in a v2.0 token only
	// with the optional claim amr.
	AMR []string
}

func AzureExchangeCode(ctx context.Context, cfg AzureADConfig, code string) (AzureIdentity, error) {
	oauthCfg := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     azureEndpoint(cfg),
		RedirectURL:  cfg.RedirectURL,
		Scopes:       []string{"openid", "profile", "email"},
	}
	token, err := oauthCfg.Exchange(ctx, code)
	if err != nil {
		return AzureIdentity{}, err
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return AzureIdentity{}, fmt.Errorf("missing id_token")
	}
	claims := jwt.MapClaims{}
	parser := jwt.NewParser()
	_, _, err = parser.ParseUnverified(rawIDToken, claims)
	if err != nil {
		return AzureIdentity{}, err
	}
	issuer, _ := claims["iss"].(string)
	if issuer != azureIssuer(cfg) {
		return AzureIdentity{}, fmt.Errorf("invalid issuer")
	}
	// The token comes straight from the token endpoint over TLS (OIDC Core
	// 3.1.3.7 lets that stand in for the signature check), but it still
	// must not be expired.
	if exp, err := claims.GetExpirationTime(); err != nil || exp == nil || time.Now().After(exp.Time) {
		return AzureIdentity{}, fmt.Errorf("id_token expired or without exp")
	}
	audience := claims["aud"]
	switch aud := audience.(type) {
	case string:
		if aud != cfg.ClientID {
			return AzureIdentity{}, fmt.Errorf("invalid audience")
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
			return AzureIdentity{}, fmt.Errorf("invalid audience")
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
			return AzureIdentity{}, fmt.Errorf("invalid audience")
		}
	default:
		return AzureIdentity{}, fmt.Errorf("invalid audience")
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
		return AzureIdentity{}, fmt.Errorf("no suitable username claim found")
	}
	oid, _ := claims["oid"].(string)
	var amr []string
	if list, ok := claims["amr"].([]any); ok {
		for _, v := range list {
			if m, ok := v.(string); ok {
				amr = append(amr, m)
			}
		}
	}
	return AzureIdentity{Username: username, Email: strings.TrimSpace(email), UPN: strings.TrimSpace(upn), OID: strings.TrimSpace(oid), AMR: amr}, nil
}

func TestAzureConnection(ctx context.Context, cfg AzureADConfig) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/%s/v2.0/.well-known/openid-configuration", cfg.authority(), cfg.TenantID), nil)
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
