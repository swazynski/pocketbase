package auth

import (
	"encoding/json"

	"golang.org/x/oauth2"
)

var _ Provider = (*GenericOidc)(nil)

// NameGenericOidc is the unique name of the generic OIDC provider.
const NameGenericOidc string = "generic-oidc"

type GenericOidc struct {
	*baseProvider
}

// NewGoogleProvider creates new generic OIDC provider instance with some defaults.
func NewGenericOidcProvider() *GenericOidc {
	return &Google{&baseProvider{
		scopes: []string{
			"profile",
			"email",
		},
		authUrl:    nil,
		tokenUrl:   nil,
		userApiUrl: nil,
	}}
}

// FetchAuthUser returns an AuthUser instance based on the response from OIDC userinfo endpoint.
func (p *GenericOidc) FetchAuthUser(token *oauth2.Token) (*AuthUser, error) {
	data, err := p.FetchRawUserData(token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err := json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	extracted := struct {
		Id      string
		Name    string
		Email   string
		Picture string
	}{}
	if err := json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	user := &AuthUser{
		Id:          extracted.Id,
		Name:        extracted.Name,
		Email:       extracted.Email,
		AvatarUrl:   extracted.Picture,
		RawUser:     rawUser,
		AccessToken: token.AccessToken,
	}

	return user, nil
}
