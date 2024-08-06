package authtest

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/pentops/j5/gen/j5/auth/v1/auth_j5pb"
	"github.com/pentops/o5-auth/internal/jwt"
	"google.golang.org/grpc/metadata"
)

type tokenOption func(*jwt.JWT)

func WithActorTags(tags map[string]string) tokenOption {
	return func(token *jwt.JWT) {
		token.ActorTags = tags
	}
}

func WithScopes(scopes []string) tokenOption {
	return func(token *jwt.JWT) {
		token.Scopes = scopes
	}
}

func WithClaim(claim *auth_j5pb.Claim) tokenOption {
	return func(token *jwt.JWT) {
		token.TenantType = claim.TenantType
		token.TenantID = claim.TenantId
		token.RealmID = claim.RealmId
		token.Scopes = claim.Scopes
	}
}

func JWTContext(ctx context.Context, opts ...tokenOption) context.Context {

	token := &jwt.JWT{
		ID:         uuid.New().String(),
		Issuer:     "test",
		Audience:   jwt.StringOrSlice{"test"},
		Subject:    fmt.Sprintf("test/%s", uuid.NewString()),
		IssuedAt:   time.Now().Unix(),
		Expires:    time.Now().Add(time.Hour).Unix(),
		NotBefore:  time.Now().Unix(),
		Scopes:     []string{},
		TenantType: "test",
		TenantID:   uuid.NewString(),
		RealmID:    uuid.NewString(),
	}

	for _, opt := range opts {
		opt(token)
	}

	jwtJSON, err := json.Marshal(token)
	if err != nil {
		panic(err)
	}

	md := metadata.MD{jwt.VerifiedJWTHeader: []string{
		string(jwtJSON),
	}}

	ctx = metadata.NewOutgoingContext(ctx, md)
	return ctx
}
