package j5auth

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pentops/j5/gen/j5/auth/v1/auth_j5pb"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestActorExtract(t *testing.T) {
	clientID := uuid.NewString()
	tenantID := uuid.NewString()

	issuedAt := time.Date(2024, 6, 14, 18, 00, 24, 0, time.UTC)

	jwt := &JWT{
		Subject:    fmt.Sprintf("%s/%s", "subjectType", clientID),
		TenantType: "tenantType",
		TenantID:   tenantID,
		IssuedAt:   1718388024,
		Scopes:     []string{"scope1"},
		Audience:   []string{"aud1", "aud2"},
		ActorTags: map[string]string{
			"name": "Bob",
		},
		ID:     "1234",
		Issuer: "https://auth.pentops.com",
	}

	actor, err := ActorFromJWT(jwt)
	if err != nil {
		t.Fatal(err)
	}

	want := &auth_j5pb.Actor{
		SubjectId:   clientID,
		SubjectType: "subjectType",
		ActorTags: map[string]string{
			"name": "Bob",
		},
		Claim: &auth_j5pb.Claim{
			Scopes:     []string{"scope1"},
			TenantType: "tenantType",
			TenantId:   tenantID,
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
	}

	if !proto.Equal(actor, want) {
		t.Logf("actor: %s", protojson.Format(actor))
		t.Logf("want:  %s", protojson.Format(want))
		t.Fatalf("actor does not match want: %v", actor)
	}

}

func TestJSONEncoding(t *testing.T) {

	t.Run("string", func(t *testing.T) {
		enc := []byte(`{"aud":"audienceString"}`)
		jj := &JWT{}
		if err := json.Unmarshal(enc, jj); err != nil {
			t.Fatal(err)
		}
		if jj.Audience[0] != "audienceString" {
			t.Fatalf("audience does not match want: %v", jj.Audience)
		}
	})

	t.Run("slice", func(t *testing.T) {
		enc := []byte(`{"aud":["a1", "a2"]}`)
		jj := &JWT{}
		if err := json.Unmarshal(enc, jj); err != nil {
			t.Fatal(err)
		}
		if jj.Audience[0] != "a1" || jj.Audience[1] != "a2" {
			t.Fatalf("audience does not match want: %v", jj.Audience)
		}
	})

}
