package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"
	"github.com/pentops/o5-auth/gen/o5/auth/v1/auth_pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	VerifiedJWTHeader = "x-verified-jwt"
)

type actionContextKey struct{}

// WithAction should only be used in test cases, otherwise use the GRPCMiddleware.
func WithAction(ctx context.Context, action *auth_pb.Action) context.Context {
	return context.WithValue(ctx, actionContextKey{}, action)
}

var ErrNoActor = status.Error(codes.Unauthenticated, "no actor in context")

func GetAction(ctx context.Context) *auth_pb.Action {
	if action, ok := ctx.Value(actionContextKey{}).(*auth_pb.Action); ok {
		return action
	}
	return nil
}

func GetAuthenticatedAction(ctx context.Context) (*auth_pb.Action, error) {
	action := GetAction(ctx)
	if action == nil {
		return nil, errors.New("no action in context")
	}
	if action.Actor == nil {
		return nil, ErrNoActor
	}
	return action, nil
}

type baseJWT struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	IssuedAt int64  `json:"iat"`
	ID       string `json:"jti"`

	Scopes []string `json:"scopes"`

	Tenant    map[string]string `json:"claims.pentops.com/tenant"`
	ActorTags map[string]string `json:"claims.pentops.com/actortags"`
}

func actorFromJWT(jwt *baseJWT) (*auth_pb.Actor, error) {
	subjectParts := strings.Split(jwt.Subject, "/")
	if len(subjectParts) != 2 {
		return nil, fmt.Errorf("invalid subject: %s", jwt.Subject)
	}
	subjectType, subjectID := subjectParts[0], subjectParts[1]
	if _, err := uuid.Parse(subjectID); err != nil {
		return nil, fmt.Errorf("invalid subject ID: %s", subjectID)
	}

	issuedAt := time.Unix(jwt.IssuedAt, 0)

	return &auth_pb.Actor{
		SubjectId:   subjectID,
		SubjectType: subjectType,
		ActorTags:   jwt.ActorTags,
		Claim: &auth_pb.Claim{
			Scopes: jwt.Scopes,
			Tenant: jwt.Tenant,
		},
		AuthenticationMethod: &auth_pb.AuthenticationMethod{
			Type: &auth_pb.AuthenticationMethod_Jwt{
				Jwt: &auth_pb.AuthenticationMethod_JWT{
					JwtId:    jwt.ID,
					Issuer:   jwt.Issuer,
					IssuedAt: timestamppb.New(issuedAt),
				},
			},
		},
	}, nil

}

func GRPCMiddleware(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	jwt, err := getSidecarJWT(ctx)
	if err != nil {
		return nil, err
	}

	if jwt == nil {
		return handler(ctx, req)
	}

	actor, err := actorFromJWT(jwt)
	if err != nil {
		return nil, err
	}

	action := &auth_pb.Action{
		Actor:  actor,
		Method: info.FullMethod,
		// TODO: Fingerprint
	}

	ctx = WithAction(ctx, action)

	return handler(ctx, req)
}

func getSidecarJWT(ctx context.Context) (*baseJWT, error) {
	incomingMD := metautils.ExtractIncoming(ctx)
	verifiedJWT := incomingMD.Get(VerifiedJWTHeader)
	if verifiedJWT == "" {
		return nil, nil
	}

	var authJWT *baseJWT
	err := json.Unmarshal([]byte(verifiedJWT), &authJWT)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal verified JWT: %w", err)
	}

	return authJWT, nil
}
