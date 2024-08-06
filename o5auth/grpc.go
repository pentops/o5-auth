package o5auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"
	"github.com/pentops/j5/gen/j5/auth/v1/auth_j5pb"
	"github.com/pentops/o5-auth/internal/jwt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type actionContextKey struct{}

// WithAction should only be used in test cases, otherwise use the GRPCMiddleware.
func WithAction(ctx context.Context, action *auth_j5pb.Action) context.Context {
	return context.WithValue(ctx, actionContextKey{}, action)
}

var ErrNoActor = status.Error(codes.Unauthenticated, "no actor in context")

func GetAction(ctx context.Context) *auth_j5pb.Action {
	if action, ok := ctx.Value(actionContextKey{}).(*auth_j5pb.Action); ok {
		return action
	}
	return nil
}

func GetAuthenticatedAction(ctx context.Context) (*auth_j5pb.Action, error) {
	action := GetAction(ctx)
	if action == nil {
		return nil, errors.New("no action in context")
	}
	if action.Actor == nil {
		return nil, ErrNoActor
	}
	return action, nil
}

func GRPCMiddleware(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	incomming, err := getSidecarJWT(ctx)
	if err != nil {
		return nil, err
	}

	if incomming == nil {
		return handler(ctx, req)
	}

	actor, err := jwt.ActorFromJWT(incomming)
	if err != nil {
		return nil, err
	}

	action := &auth_j5pb.Action{
		Actor:  actor,
		Method: info.FullMethod,
		// TODO: Fingerprint
	}

	ctx = WithAction(ctx, action)

	return handler(ctx, req)
}

func getSidecarJWT(ctx context.Context) (*jwt.JWT, error) {
	incomingMD := metautils.ExtractIncoming(ctx)
	verifiedJWT := incomingMD.Get(jwt.VerifiedJWTHeader)
	if verifiedJWT == "" {
		return nil, nil
	}

	var authJWT *jwt.JWT
	err := json.Unmarshal([]byte(verifiedJWT), &authJWT)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal verified JWT: %w", err)
	}

	return authJWT, nil
}
