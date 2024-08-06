package o5auth

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pentops/j5/gen/j5/auth/v1/auth_j5pb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type JWT struct {
	ID        string        `json:"jti"`
	Issuer    string        `json:"iss"`
	Audience  StringOrSlice `json:"aud"`
	Subject   string        `json:"sub"`
	IssuedAt  int64         `json:"iat"`
	Expires   int64         `json:"exp"`
	NotBefore int64         `json:"nbf"`

	Scopes []string `json:"scopes"`

	TenantType string            `json:"claims.pentops.com/tenant"`
	TenantID   string            `json:"claims.pentops.com/tenantid"`
	RealmID    string            `json:"claims.pentops.com/realmid"`
	ActorTags  map[string]string `json:"claims.pentops.com/actortags"`
}

type StringOrSlice []string

func (s *StringOrSlice) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data")
	}
	if data[0] == '[' {
		var slice []string
		if err := json.Unmarshal(data, &slice); err != nil {
			return err
		}
		*s = slice
		return nil
	}

	if data[0] != '"' {
		return fmt.Errorf("expected string or slice, got %s", data)
	}

	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	*s = []string{str}

	return nil
}

func ActorFromJWT(jwt *JWT) (*auth_j5pb.Actor, error) {
	subjectParts := strings.Split(jwt.Subject, "/")
	if len(subjectParts) != 2 {
		return nil, fmt.Errorf("invalid subject: %s", jwt.Subject)
	}
	subjectType, subjectID := subjectParts[0], subjectParts[1]
	if _, err := uuid.Parse(subjectID); err != nil {
		return nil, fmt.Errorf("invalid subject ID: %s", subjectID)
	}

	issuedAt := time.Unix(jwt.IssuedAt, 0)

	return &auth_j5pb.Actor{
		SubjectId:   subjectID,
		SubjectType: subjectType,
		ActorTags:   jwt.ActorTags,
		Claim: &auth_j5pb.Claim{
			Scopes:     jwt.Scopes,
			TenantType: jwt.TenantType,
			RealmId:    jwt.RealmID,
			TenantId:   jwt.TenantID,
		},
		AuthenticationMethod: &auth_j5pb.AuthenticationMethod{
			Type: &auth_j5pb.AuthenticationMethod_Jwt{
				Jwt: &auth_j5pb.AuthenticationMethod_JWT{
					JwtId:    jwt.ID,
					Issuer:   jwt.Issuer,
					IssuedAt: timestamppb.New(issuedAt),
				},
			},
		},
	}, nil

}
