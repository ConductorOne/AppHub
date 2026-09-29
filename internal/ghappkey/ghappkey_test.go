// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package ghappkey_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/internal/ghappkey"
)

const testParameter = "/apphub/test/github-app/private-key"

type fakeAPI struct {
	stored                          string
	putErr, descErr, delErr, getErr error
	putCalls                        int
}

func (f *fakeAPI) PutParameter(_ context.Context, in *ssm.PutParameterInput, _ ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
	f.putCalls++
	if f.putErr != nil {
		return nil, f.putErr
	}
	f.stored = aws.ToString(in.Value)
	return &ssm.PutParameterOutput{}, nil
}
func (f *fakeAPI) DescribeParameters(_ context.Context, _ *ssm.DescribeParametersInput, _ ...func(*ssm.Options)) (*ssm.DescribeParametersOutput, error) {
	if f.descErr != nil {
		return nil, f.descErr
	}
	if f.stored == "" {
		return &ssm.DescribeParametersOutput{}, nil
	}
	return &ssm.DescribeParametersOutput{Parameters: []ssmtypes.ParameterMetadata{{Name: aws.String(testParameter)}}}, nil
}
func (f *fakeAPI) DeleteParameter(_ context.Context, _ *ssm.DeleteParameterInput, _ ...func(*ssm.Options)) (*ssm.DeleteParameterOutput, error) {
	if f.delErr != nil {
		return nil, f.delErr
	}
	if f.stored == "" {
		return nil, &ssmtypes.ParameterNotFound{}
	}
	f.stored = ""
	return &ssm.DeleteParameterOutput{}, nil
}
func (f *fakeAPI) GetParameter(_ context.Context, _ *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.stored == "" {
		return nil, &ssmtypes.ParameterNotFound{}
	}
	return &ssm.GetParameterOutput{Parameter: &ssmtypes.Parameter{Value: aws.String(f.stored)}}, nil
}

func testConfig() ghappkey.Config {
	return ghappkey.Config{Region: "us-east-1", ParameterName: testParameter}
}

func TestStoreWriteExistDeleteRoundTrip(t *testing.T) {
	fake := &fakeAPI{}
	store, err := ghappkey.NewStoreWithAPI(fake, testConfig())
	if err != nil {
		t.Fatalf("NewStoreWithAPI: %v", err)
	}
	ctx := context.Background()

	if exists, err := store.Exists(ctx); err != nil || exists {
		t.Fatalf("Exists before Put = %v, %v", exists, err)
	}
	if err := store.Put(ctx, credentials.NewSecret("-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if exists, err := store.Exists(ctx); err != nil || !exists {
		t.Fatalf("Exists after Put = %v, %v", exists, err)
	}
	if err := store.Delete(ctx); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if exists, err := store.Exists(ctx); err != nil || exists {
		t.Fatalf("Exists after Delete = %v, %v", exists, err)
	}
	// Deleting an already-absent key is not an error.
	if err := store.Delete(ctx); err != nil {
		t.Fatalf("Delete of absent key: %v", err)
	}
}

func TestStorePutRejectsABlankKey(t *testing.T) {
	fake := &fakeAPI{}
	store, err := ghappkey.NewStoreWithAPI(fake, testConfig())
	if err != nil {
		t.Fatalf("NewStoreWithAPI: %v", err)
	}
	if err := store.Put(context.Background(), credentials.NewSecret("   \n")); !errors.Is(err, ghappkey.ErrInvalidKey) {
		t.Fatalf("Put(blank) = %v, want ErrInvalidKey", err)
	}
	if fake.putCalls != 0 {
		t.Fatal("a blank key reached the API")
	}
}

func TestReaderGetReturnsTheStoredKey(t *testing.T) {
	fake := &fakeAPI{stored: "the-pem"}
	reader, err := ghappkey.NewReaderWithAPI(fake, testConfig())
	if err != nil {
		t.Fatalf("NewReaderWithAPI: %v", err)
	}
	got, err := reader.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if credentials.Reveal(got) != "the-pem" {
		t.Fatalf("Get = %q, want %q", credentials.Reveal(got), "the-pem")
	}
}

func TestReaderGetReportsNotFound(t *testing.T) {
	reader, err := ghappkey.NewReaderWithAPI(&fakeAPI{}, testConfig())
	if err != nil {
		t.Fatalf("NewReaderWithAPI: %v", err)
	}
	if _, err := reader.Get(context.Background()); !errors.Is(err, ghappkey.ErrNotFound) {
		t.Fatalf("Get(absent) = %v, want ErrNotFound", err)
	}
}

func TestTransportFailuresDoNotLeakThroughUnavailable(t *testing.T) {
	sentinel := "aws-transport-canary-should-never-appear"
	fake := &fakeAPI{putErr: errors.New(sentinel), descErr: errors.New(sentinel), delErr: errors.New(sentinel), getErr: errors.New(sentinel)}
	store, err := ghappkey.NewStoreWithAPI(fake, testConfig())
	if err != nil {
		t.Fatalf("NewStoreWithAPI: %v", err)
	}
	reader, err := ghappkey.NewReaderWithAPI(fake, testConfig())
	if err != nil {
		t.Fatalf("NewReaderWithAPI: %v", err)
	}

	errs := []error{}
	if err := store.Put(context.Background(), credentials.NewSecret("key")); err != nil {
		errs = append(errs, err)
	}
	if _, err := store.Exists(context.Background()); err != nil {
		errs = append(errs, err)
	}
	if err := store.Delete(context.Background()); err != nil {
		errs = append(errs, err)
	}
	if _, err := reader.Get(context.Background()); err != nil {
		errs = append(errs, err)
	}
	if len(errs) != 4 {
		t.Fatalf("expected all four calls to fail, got %d errors", len(errs))
	}
	for _, e := range errs {
		if !errors.Is(e, ghappkey.ErrUnavailable) {
			t.Errorf("error %v does not classify as ErrUnavailable", e)
		}
		if strings.Contains(e.Error(), sentinel) {
			t.Errorf("transport error text leaked: %v", e)
		}
	}
}

func TestConfigRequiresRegionAndParameterName(t *testing.T) {
	for _, cfg := range []ghappkey.Config{{}, {Region: "us-east-1"}, {ParameterName: testParameter}} {
		if _, err := ghappkey.NewStoreWithAPI(&fakeAPI{}, cfg); !errors.Is(err, ghappkey.ErrConfiguration) {
			t.Errorf("NewStoreWithAPI(%+v) = %v, want ErrConfiguration", cfg, err)
		}
		if _, err := ghappkey.NewReaderWithAPI(&fakeAPI{}, cfg); !errors.Is(err, ghappkey.ErrConfiguration) {
			t.Errorf("NewReaderWithAPI(%+v) = %v, want ErrConfiguration", cfg, err)
		}
	}
}
