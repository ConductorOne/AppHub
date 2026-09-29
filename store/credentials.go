// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/credentials/lifecycle"
)

// Key layout for credential records. Ported unchanged from
// internal/database/credential.go:15,57-66 -- the shapes are the same because
// the queries are the same, and changing a key layout is a data migration
// rather than a port.
//
// gosec's G101 flags three of these because the constant names contain "Cred"
// and the values are string literals. They are key prefixes and an entity-type
// discriminator -- no credential material is expressible here, which is the
// property credentialItem is built around. Suppressed per-line with a reason
// rather than by disabling the rule, which would also stop it firing on a real
// one.
const (
	pkPrefixCredential = "CREDENTIAL#"      //nolint:gosec // DynamoDB partition-key prefix, not a credential
	entityCredential   = "VendedCredential" //nolint:gosec // Type attribute discriminator, not a credential

	gsi1PKPrefixOwner = "CREDOWNER#"
	gsi1SKPrefixCred  = "CREDENTIAL#" //nolint:gosec // GSI1 sort-key prefix, not a credential
)

// CredentialRecords implements lifecycle.Records on DynamoDB.
//
// It is the whole reason store exists as a package: lifecycle declares what it
// needs persisted, this type is the only thing that knows the answer involves
// partition keys, and no lifecycle.Record that leaves here carries a trace of
// how it was stored.
//
// Ported from internal/database/credential.go (CredentialRepository, 321 lines),
// with the four behavioural changes docs/design/credential-vending.md §2.2
// specifies: ErrNotFound instead of (nil, nil), Revision-guarded updates,
// allowlisted annotations, and ExpiryAuthoritative.
type CredentialRecords struct {
	client      *Client
	annotations *lifecycle.AnnotationRegistry
}

// Compile-time proof that the fence's one job is done. If this stops compiling,
// the port and the port's consumer have diverged.
var _ lifecycle.Records = (*CredentialRecords)(nil)

// NewCredentialRecords builds the DynamoDB-backed Records implementation.
//
// The annotation registry is required rather than optional. A nil registry would
// have to mean either "allow everything" or "allow nothing"; the first reopens
// the hole the allowlist exists to close, and the second is a store that
// silently fails every write that carries context. Refusing to construct is the
// only option that cannot be misread.
func NewCredentialRecords(client *Client, annotations *lifecycle.AnnotationRegistry) (*CredentialRecords, error) {
	if client == nil {
		return nil, errors.New("store: client is required")
	}
	if annotations == nil {
		return nil, errors.New("store: annotation registry is required (see lifecycle.NewAnnotationRegistry)")
	}
	return &CredentialRecords{client: client, annotations: annotations}, nil
}

// credentialItem is the stored shape of a lifecycle.Record.
//
// It is unexported, and so are its dynamodbav tags' consequences: the tags are
// the single most contagious DynamoDB detail in the source system (1,456 of them
// across internal/database/), and keeping the tagged struct private is what stops
// them spreading. lifecycle.Record has no tags and never will.
//
// The field set is the source's VendedCredential (credential.go:18-41) plus the
// fields §2.2 adds. Note what is absent: nothing here can hold credential
// material, matching the same property on lifecycle.Record.
type credentialItem struct {
	PK     string `dynamodbav:"PK"`
	SK     string `dynamodbav:"SK"`
	Type   string `dynamodbav:"Type"`
	GSI1PK string `dynamodbav:"GSI1PK,omitempty"`
	GSI1SK string `dynamodbav:"GSI1SK,omitempty"`

	ID string `dynamodbav:"ID"`

	// Revision is the optimistic-concurrency counter. New in the port: the
	// source's Update was a whole-item PutItem guarded only by
	// attribute_exists(PK), so the last writer won and the loser was never told
	// (credential.go:105-119).
	Revision uint64 `dynamodbav:"Revision"`

	ProviderID     string `dynamodbav:"ProviderID"`
	CredentialType string `dynamodbav:"CredentialType"`
	Name           string `dynamodbav:"Name"`
	PlatformKeyID  string `dynamodbav:"PlatformKeyID"`
	IdempotencyKey string `dynamodbav:"IdempotencyKey,omitempty"`

	RequesterID    string `dynamodbav:"RequesterID"`
	RequesterType  string `dynamodbav:"RequesterType"`
	RequesterEmail string `dynamodbav:"RequesterEmail,omitempty"`

	Status        string `dynamodbav:"Status"`
	RevokeOutcome string `dynamodbav:"RevokeOutcome,omitempty"`

	GrantedScope   []string `dynamodbav:"GrantedScope,omitempty"`
	RequestedScope []string `dynamodbav:"RequestedScope,omitempty"`

	ApplicationID string `dynamodbav:"ApplicationID,omitempty"`

	// The secret locator, flattened. A nested struct would marshal to a DynamoDB
	// map, which is harder to project and filter on for no gain.
	SecretStore   string `dynamodbav:"SecretStore,omitempty"`
	SecretName    string `dynamodbav:"SecretName,omitempty"`
	SecretVersion string `dynamodbav:"SecretVersion,omitempty"`
	SecretEnvVar  string `dynamodbav:"SecretEnvVar,omitempty"`

	Annotations map[string]string `dynamodbav:"Annotations,omitempty"`

	// Every timestamp below is an instant, not a time.Time, and that is
	// load-bearing rather than stylistic: instant is the only encoding in this
	// package whose lexical order is its temporal order. See store/instant.go for
	// the three defects that came from not having it.
	//
	// ExpiresAt carries no omitempty deliberately: the attribute must always
	// exist so ListExpiring can exclude never-expiring records with a filter
	// instead of shipping every one of them to the client and dropping them here.
	ExpiresAt           instant `dynamodbav:"ExpiresAt"`
	ExpiryAuthoritative bool    `dynamodbav:"ExpiryAuthoritative"`

	CreatedAt       instant  `dynamodbav:"CreatedAt"`
	UpdatedAt       instant  `dynamodbav:"UpdatedAt,omitempty"`
	LastRefreshedAt instant  `dynamodbav:"LastRefreshedAt,omitempty"`
	RevokedAt       *instant `dynamodbav:"RevokedAt,omitempty"`
}

// Create writes a new record, failing rather than overwriting.
func (r *CredentialRecords) Create(ctx context.Context, rec *lifecycle.Record) error {
	if rec == nil {
		return errors.New("store: record is required")
	}
	// The issuer assigns the ID before calling the provider, so that a vend which
	// fails halfway still has something to reconcile
	// (docs/design/credential-vending.md §2.4). The source minted a UUID here
	// instead (credential.go:54-56), which cannot support write-ahead ordering:
	// if persistence names the credential, persistence has to run first, and then
	// nothing is written ahead of anything.
	if rec.ID == "" {
		return errors.New("store: record ID is required; the issuer assigns it before vending")
	}
	if rec.Status == "" {
		// The source defaulted an empty status to "active" (credential.go:61-63).
		// Under the ported lifecycle that default is dangerous: a record written
		// ahead of a provider call is StatusPending, and silently relabelling it
		// active would tell the reconciler a credential is live and confirmed when
		// nothing has confirmed it.
		return errors.New("store: record Status is required; store does not default it")
	}
	if err := r.annotations.Validate(rec.ProviderID, rec.Annotations); err != nil {
		return fmt.Errorf("store: create credential %s: %w", rec.ID, err)
	}

	item := itemFromRecord(rec)
	item.Revision = 1

	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return fmt.Errorf("store: marshal credential: %w", err)
	}

	_, err = r.client.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(r.client.tableName),
		Item:                av,
		ConditionExpression: aws.String("attribute_not_exists(PK)"),
	})
	if err != nil {
		if conditionFailed(err) {
			return fmt.Errorf("%w: %s", lifecycle.ErrAlreadyExists, rec.ID)
		}
		return fmt.Errorf("store: create credential: %w", err)
	}

	rec.Revision = item.Revision
	return nil
}

// Update writes an existing record if rec.Revision still matches what is stored.
//
// This is the fix for the race in docs/design/credential-vending.md §2.2 item 3:
// the expiry scheduler (jobs/credential_scheduler.go:102-109) and the revoke
// handler (services/credential.go:1045-1056) both wrote the whole record with
// only attribute_exists(PK) to guard them, so a scheduler pass could overwrite an
// operator's revoke with an expiry a moment later and no one would learn of it.
func (r *CredentialRecords) Update(ctx context.Context, rec *lifecycle.Record) error {
	if rec == nil {
		return errors.New("store: record is required")
	}
	if rec.ID == "" {
		return errors.New("store: record ID is required")
	}
	if err := r.annotations.Validate(rec.ProviderID, rec.Annotations); err != nil {
		return fmt.Errorf("store: update credential %s: %w", rec.ID, err)
	}

	expected := rec.Revision
	item := itemFromRecord(rec)
	item.Revision = expected + 1

	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return fmt.Errorf("store: marshal credential: %w", err)
	}

	_, err = r.client.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(r.client.tableName),
		Item:                av,
		ConditionExpression: aws.String("attribute_exists(PK) AND Revision = :rev"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":rev": revisionAttr(expected),
		},
		// A bare condition failure cannot distinguish "gone" from "someone wrote
		// first", and the two call for opposite responses: one is terminal, the
		// other is a retry. Asking for the old item on failure is what lets this
		// return the right sentinel instead of guessing.
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	})
	if err != nil {
		if conditionFailed(err) {
			var cfe *types.ConditionalCheckFailedException
			_ = errors.As(err, &cfe)
			if cfe == nil || len(cfe.Item) == 0 {
				return fmt.Errorf("%w: %s", lifecycle.ErrNotFound, rec.ID)
			}
			return fmt.Errorf("%w: %s", lifecycle.ErrConflict, rec.ID)
		}
		return fmt.Errorf("store: update credential: %w", err)
	}

	// Documented on lifecycle.Records.Update: on success the stored revision has
	// moved on, so the caller's copy moves with it and can keep writing.
	rec.Revision = item.Revision
	return nil
}

// Get returns the record for id, or lifecycle.ErrNotFound.
func (r *CredentialRecords) Get(ctx context.Context, id string) (*lifecycle.Record, error) {
	if id == "" {
		return nil, fmt.Errorf("%w: empty ID", lifecycle.ErrNotFound)
	}

	out, err := r.client.api.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(r.client.tableName),
		Key:       credentialKey(id),
	})
	if err != nil {
		return nil, fmt.Errorf("store: get credential: %w", err)
	}
	// The source returned (nil, nil) here (credential.go:95-97), which the
	// compiler cannot make anyone check -- so a caller that forgot dereferenced
	// nil in the revoke path. A sentinel makes the absent case unskippable.
	if len(out.Item) == 0 {
		return nil, fmt.Errorf("%w: %s", lifecycle.ErrNotFound, id)
	}

	var item credentialItem
	if err := attributevalue.UnmarshalMap(out.Item, &item); err != nil {
		return nil, fmt.Errorf("store: unmarshal credential: %w", err)
	}
	rec := item.toRecord()
	return &rec, nil
}

// Delete removes a record, returning lifecycle.ErrNotFound if there was none.
//
// The source's Delete was unconditional and reported success for an ID that
// never existed (credential.go:121-133). Since deleting is an administrative act
// on an audit trail, "there was nothing there" is the one thing the operator most
// needs to hear -- a silent success on a mistyped ID reads as a completed
// cleanup.
func (r *CredentialRecords) Delete(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("%w: empty ID", lifecycle.ErrNotFound)
	}

	_, err := r.client.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:           aws.String(r.client.tableName),
		Key:                 credentialKey(id),
		ConditionExpression: aws.String("attribute_exists(PK)"),
	})
	if err != nil {
		if conditionFailed(err) {
			return fmt.Errorf("%w: %s", lifecycle.ErrNotFound, id)
		}
		return fmt.Errorf("store: delete credential: %w", err)
	}
	return nil
}

// ListByRequester returns a requester's records, newest first.
//
// The one query in this file that is not a Scan: GSI1 is keyed by owner, so this
// reads a single partition (credential.go:135-154).
func (r *CredentialRecords) ListByRequester(ctx context.Context, requesterID string) ([]lifecycle.Record, error) {
	if requesterID == "" {
		return nil, errors.New("store: requester ID is required")
	}

	var out []lifecycle.Record
	var lastKey map[string]types.AttributeValue
	for {
		page, err := r.client.api.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(r.client.tableName),
			IndexName:              aws.String(indexGSI1),
			KeyConditionExpression: aws.String("GSI1PK = :pk AND begins_with(GSI1SK, :skPrefix)"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk":       &types.AttributeValueMemberS{Value: gsi1PKPrefixOwner + requesterID},
				":skPrefix": &types.AttributeValueMemberS{Value: gsi1SKPrefixCred},
			},
			ScanIndexForward:  aws.Bool(false),
			ExclusiveStartKey: lastKey,
		})
		if err != nil {
			return nil, fmt.Errorf("store: list credentials by requester: %w", err)
		}
		recs, err := recordsFromItems(page.Items)
		if err != nil {
			return nil, err
		}
		out = append(out, recs...)

		// The source did not paginate this Query at all (credential.go:136-153):
		// it read the first page and returned it as if it were the whole answer,
		// so a requester with more than 1 MB of records silently lost the tail.
		if len(page.LastEvaluatedKey) == 0 {
			return out, nil
		}
		lastKey = page.LastEvaluatedKey
	}
}

// ListByApplication returns records vended for an application.
//
// A Scan with a filter, as in the source (credential.go:196-236). See the Scan
// note on scanPages.
func (r *CredentialRecords) ListByApplication(ctx context.Context, applicationID string, activeOnly bool) ([]lifecycle.Record, error) {
	if applicationID == "" {
		return nil, errors.New("store: application ID is required")
	}

	filter := "#type = :type AND #appID = :appID"
	names := map[string]string{"#type": "Type", "#appID": "ApplicationID"}
	values := map[string]types.AttributeValue{
		":type":  &types.AttributeValueMemberS{Value: entityCredential},
		":appID": &types.AttributeValueMemberS{Value: applicationID},
	}
	if activeOnly {
		filter += " AND #status = :active"
		names["#status"] = "Status"
		values[":active"] = &types.AttributeValueMemberS{Value: string(lifecycle.StatusActive)}
	}

	return r.scanPages(ctx, filter, names, values, "list credentials by application", nil)
}

// ListByStatus returns every record in a given status.
//
// Generalises the source's ListPendingRevoke (credential.go:240-278), which
// hard-coded the one status its caller needed.
func (r *CredentialRecords) ListByStatus(ctx context.Context, status lifecycle.Status) ([]lifecycle.Record, error) {
	if status == "" {
		return nil, errors.New("store: status is required")
	}

	return r.scanPages(ctx,
		"#type = :type AND #status = :status",
		map[string]string{"#type": "Type", "#status": "Status"},
		map[string]types.AttributeValue{
			":type":   &types.AttributeValueMemberS{Value: entityCredential},
			":status": &types.AttributeValueMemberS{Value: string(status)},
		},
		"list credentials by status", nil)
}

// ListExpiring returns non-terminal records whose ExpiresAt is at or before at.
//
// Ported from ListExpired (credential.go:281-321) with two corrections the new
// contract requires:
//
// The source filtered on Status = "active" only. The interface says non-terminal,
// which also covers pending and pending_revoke -- a credential that expired while
// its vend was still unconfirmed is exactly the case the reconciler must see.
//
// The filter compares a stored string lexically, so it is only a temporal
// comparison because of how instants are encoded -- see store/instant.go, which
// states and tests the requirement that byte order be chronological order. Three
// defects in this package came from that not holding: a variable-width fractional
// part, the same in a sort key, and an expiry written in a +14:00 zone that sorted
// a year above the bound and so was never swept at all.
//
// expiryFilter still makes the final decision in Go. The filter expression is an
// optimisation that keeps the reconciler from reading the whole table; the
// authoritative answer is Record.Expired.
func (r *CredentialRecords) ListExpiring(ctx context.Context, at time.Time) ([]lifecycle.Record, error) {
	filter := "#type = :type AND ExpiresAt > :zeroExpiry AND ExpiresAt <= :bound" +
		" AND #status <> :revoked AND #status <> :expired AND #status <> :orphaned"

	return r.scanPages(ctx, filter,
		map[string]string{"#type": "Type", "#status": "Status"},
		map[string]types.AttributeValue{
			":type":       &types.AttributeValueMemberS{Value: entityCredential},
			":zeroExpiry": &types.AttributeValueMemberS{Value: instantZero},
			":bound":      &types.AttributeValueMemberS{Value: encodeInstant(at)},
			":revoked":    &types.AttributeValueMemberS{Value: string(lifecycle.StatusRevoked)},
			":expired":    &types.AttributeValueMemberS{Value: string(lifecycle.StatusExpired)},
			":orphaned":   &types.AttributeValueMemberS{Value: string(lifecycle.StatusOrphaned)},
		},
		"list expiring credentials",
		expiryFilter(at))
}

// scanPages runs a paginated Scan and converts the results.
//
// Every caller of this is a full-table Scan with a filter expression, inherited
// from the source, and it is a known scaling problem: DynamoDB filters after
// reading, so cost grows with the table rather than with the answer. It is
// recorded here rather than hidden, and it is not fixed here -- the fix is a
// GSI keyed by status and expiry, which is a schema change and its own ticket.
// lifecycle.Records does not encode the Scan, so that change stays inside this
// package.
//
// keep, when non-nil, is applied after DynamoDB's own filter for conditions that
// a filter expression cannot decide correctly.
func (r *CredentialRecords) scanPages(
	ctx context.Context,
	filter string,
	names map[string]string,
	values map[string]types.AttributeValue,
	what string,
	keep func(lifecycle.Record) bool,
) ([]lifecycle.Record, error) {
	var out []lifecycle.Record
	var lastKey map[string]types.AttributeValue
	for {
		page, err := r.client.api.Scan(ctx, &dynamodb.ScanInput{
			TableName:                 aws.String(r.client.tableName),
			FilterExpression:          aws.String(filter),
			ExpressionAttributeNames:  names,
			ExpressionAttributeValues: values,
			ExclusiveStartKey:         lastKey,
		})
		if err != nil {
			return nil, fmt.Errorf("store: %s: %w", what, err)
		}
		recs, err := recordsFromItems(page.Items)
		if err != nil {
			return nil, err
		}
		for _, rec := range recs {
			if keep == nil || keep(rec) {
				out = append(out, rec)
			}
		}
		if len(page.LastEvaluatedKey) == 0 {
			return out, nil
		}
		lastKey = page.LastEvaluatedKey
	}
}

// expiryFilter is the authoritative expiry decision, made in Go because a
// DynamoDB filter expression cannot make it correctly: see ListExpiring.
func expiryFilter(at time.Time) func(lifecycle.Record) bool {
	return func(rec lifecycle.Record) bool {
		return !rec.Status.Terminal() && rec.Expired(at)
	}
}

func credentialKey(id string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		attrPK: &types.AttributeValueMemberS{Value: pkPrefixCredential + id},
		attrSK: &types.AttributeValueMemberS{Value: skMetadata},
	}
}

// revisionAttr renders a revision as a DynamoDB number.
func revisionAttr(rev uint64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", rev)}
}

func recordsFromItems(items []map[string]types.AttributeValue) ([]lifecycle.Record, error) {
	var stored []credentialItem
	if err := attributevalue.UnmarshalListOfMaps(items, &stored); err != nil {
		return nil, fmt.Errorf("store: unmarshal credentials: %w", err)
	}
	out := make([]lifecycle.Record, 0, len(stored))
	for i := range stored {
		out = append(out, stored[i].toRecord())
	}
	return out, nil
}

func itemFromRecord(rec *lifecycle.Record) credentialItem {
	item := credentialItem{
		PK:     pkPrefixCredential + rec.ID,
		SK:     skMetadata,
		Type:   entityCredential,
		GSI1PK: gsi1PKPrefixOwner + rec.Requester.ID,
		GSI1SK: gsi1SKPrefixCred + encodeInstant(rec.CreatedAt),

		ID:             rec.ID,
		Revision:       rec.Revision,
		ProviderID:     rec.ProviderID,
		CredentialType: string(rec.Type),
		Name:           rec.Name,
		PlatformKeyID:  rec.PlatformKeyID,
		IdempotencyKey: rec.IdempotencyKey,

		RequesterID:    rec.Requester.ID,
		RequesterType:  rec.Requester.Type,
		RequesterEmail: rec.Requester.Email,

		Status:        string(rec.Status),
		RevokeOutcome: string(rec.RevokeOutcome),

		GrantedScope:   rec.GrantedScope,
		RequestedScope: rec.RequestedScope,

		ApplicationID: rec.ApplicationID,

		SecretStore:   rec.SecretRef.Store,
		SecretName:    rec.SecretRef.Name,
		SecretVersion: rec.SecretRef.Version,
		SecretEnvVar:  rec.SecretRef.EnvVar,

		ExpiresAt:           instant(rec.ExpiresAt),
		ExpiryAuthoritative: rec.ExpiryAuthoritative,

		CreatedAt:       instant(rec.CreatedAt),
		UpdatedAt:       instant(rec.UpdatedAt),
		LastRefreshedAt: instant(rec.LastRefreshedAt),
	}

	if rec.RevokedAt != nil {
		at := instant(*rec.RevokedAt)
		item.RevokedAt = &at
	}

	if len(rec.Annotations) > 0 {
		item.Annotations = make(map[string]string, len(rec.Annotations))
		for k, v := range rec.Annotations {
			item.Annotations[string(k)] = v
		}
	}
	return item
}

func (i credentialItem) toRecord() lifecycle.Record {
	rec := lifecycle.Record{
		ID:             i.ID,
		Revision:       i.Revision,
		ProviderID:     i.ProviderID,
		Type:           credentials.CredentialType(i.CredentialType),
		Name:           i.Name,
		PlatformKeyID:  i.PlatformKeyID,
		IdempotencyKey: i.IdempotencyKey,
		Requester: lifecycle.Requester{
			ID:    i.RequesterID,
			Type:  i.RequesterType,
			Email: i.RequesterEmail,
		},
		Status:         lifecycle.Status(i.Status),
		RevokeOutcome:  lifecycle.RevokeOutcome(i.RevokeOutcome),
		GrantedScope:   i.GrantedScope,
		RequestedScope: i.RequestedScope,
		ApplicationID:  i.ApplicationID,
		SecretRef: credentials.SecretRef{
			Store:   i.SecretStore,
			Name:    i.SecretName,
			Version: i.SecretVersion,
			EnvVar:  i.SecretEnvVar,
		},
		ExpiresAt:           i.ExpiresAt.Time(),
		ExpiryAuthoritative: i.ExpiryAuthoritative,
		CreatedAt:           i.CreatedAt.Time(),
		UpdatedAt:           i.UpdatedAt.Time(),
		LastRefreshedAt:     i.LastRefreshedAt.Time(),
	}

	if i.RevokedAt != nil {
		at := i.RevokedAt.Time()
		rec.RevokedAt = &at
	}

	if len(i.Annotations) > 0 {
		rec.Annotations = make(lifecycle.Annotations, len(i.Annotations))
		for k, v := range i.Annotations {
			rec.Annotations[lifecycle.AnnotationKey(k)] = v
		}
	}
	return rec
}
