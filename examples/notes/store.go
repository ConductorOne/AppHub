// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// Note is one user's note.
type Note struct {
	ID        string    `json:"id"`
	Text      string    `json:"text"`
	CreatedAt time.Time `json:"createdAt"`
}

// ErrNotFound means the note does not exist for this owner.
var ErrNotFound = errors.New("note not found")

// Store keeps notes per owner.
type Store interface {
	List(ctx context.Context, owner string, limit int32) ([]Note, error)
	Create(ctx context.Context, owner, text string) (Note, error)
	Delete(ctx context.Context, owner, id string) error
}

// The table is keyed by the string attributes pk and sk, AppHub's defaults for
// a key-value table. Every note of one owner shares a partition, so listing an
// owner's notes is a single Query and needs no index:
//
//	pk = "USER#<email>"   sk = "NOTE#<id>"
const (
	attrPK        = "pk"
	attrSK        = "sk"
	attrText      = "text"
	attrCreatedAt = "createdAt"
	ownerPrefix   = "USER#"
	notePrefix    = "NOTE#"
)

// DynamoStore is a Store on one DynamoDB table.
type DynamoStore struct {
	client *dynamodb.Client
	table  string
}

// NewDynamoStore returns a Store backed by table.
func NewDynamoStore(client *dynamodb.Client, table string) *DynamoStore {
	return &DynamoStore{client: client, table: table}
}

func ownerKey(owner string) string { return ownerPrefix + owner }
func noteKey(id string) string     { return notePrefix + id }

// newNoteID returns an ID that sorts in creation order: zero-padded Unix
// nanoseconds, then random bytes so two notes created in the same instant differ.
func newNoteID(now time.Time) (string, error) {
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return "", fmt.Errorf("generating note id: %w", err)
	}
	return fmt.Sprintf("%020d-%s", now.UnixNano(), hex.EncodeToString(suffix)), nil
}

func noteItem(owner string, n Note) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		attrPK:        &types.AttributeValueMemberS{Value: ownerKey(owner)},
		attrSK:        &types.AttributeValueMemberS{Value: noteKey(n.ID)},
		attrText:      &types.AttributeValueMemberS{Value: n.Text},
		attrCreatedAt: &types.AttributeValueMemberS{Value: n.CreatedAt.Format(time.RFC3339Nano)},
	}
}

func noteFromItem(item map[string]types.AttributeValue) (Note, error) {
	str := func(name string) (string, error) {
		v, ok := item[name].(*types.AttributeValueMemberS)
		if !ok {
			return "", fmt.Errorf("item attribute %q is missing or not a string", name)
		}
		return v.Value, nil
	}
	sk, err := str(attrSK)
	if err != nil {
		return Note{}, err
	}
	text, err := str(attrText)
	if err != nil {
		return Note{}, err
	}
	created, err := str(attrCreatedAt)
	if err != nil {
		return Note{}, err
	}
	at, err := time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return Note{}, fmt.Errorf("item attribute %q: %w", attrCreatedAt, err)
	}
	return Note{ID: strings.TrimPrefix(sk, notePrefix), Text: text, CreatedAt: at}, nil
}

// List returns the owner's newest notes first.
func (s *DynamoStore) List(ctx context.Context, owner string, limit int32) ([]Note, error) {
	out, err := s.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(s.table),
		KeyConditionExpression: aws.String("#pk = :pk AND begins_with(#sk, :note)"),
		ExpressionAttributeNames: map[string]string{
			"#pk": attrPK,
			"#sk": attrSK,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk":   &types.AttributeValueMemberS{Value: ownerKey(owner)},
			":note": &types.AttributeValueMemberS{Value: notePrefix},
		},
		ScanIndexForward: aws.Bool(false),
		Limit:            aws.Int32(limit),
	})
	if err != nil {
		return nil, fmt.Errorf("querying notes in table %s: %w", s.table, err)
	}
	notes := make([]Note, 0, len(out.Items))
	for _, item := range out.Items {
		n, err := noteFromItem(item)
		if err != nil {
			return nil, fmt.Errorf("reading note in table %s: %w", s.table, err)
		}
		notes = append(notes, n)
	}
	return notes, nil
}

// Create stores a new note for owner.
func (s *DynamoStore) Create(ctx context.Context, owner, text string) (Note, error) {
	now := time.Now().UTC()
	id, err := newNoteID(now)
	if err != nil {
		return Note{}, err
	}
	n := Note{ID: id, Text: text, CreatedAt: now}
	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.table),
		Item:      noteItem(owner, n),
		// The ID is unique, so this only fails on a collision, which would
		// otherwise silently overwrite another note.
		ConditionExpression:      aws.String("attribute_not_exists(#pk)"),
		ExpressionAttributeNames: map[string]string{"#pk": attrPK},
	})
	if err != nil {
		return Note{}, fmt.Errorf("writing note to table %s: %w", s.table, err)
	}
	return n, nil
}

// Delete removes one of the owner's notes. Another owner's note is ErrNotFound,
// because the key includes the owner.
func (s *DynamoStore) Delete(ctx context.Context, owner, id string) error {
	_, err := s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(s.table),
		Key: map[string]types.AttributeValue{
			attrPK: &types.AttributeValueMemberS{Value: ownerKey(owner)},
			attrSK: &types.AttributeValueMemberS{Value: noteKey(id)},
		},
		ConditionExpression:      aws.String("attribute_exists(#pk)"),
		ExpressionAttributeNames: map[string]string{"#pk": attrPK},
	})
	var missing *types.ConditionalCheckFailedException
	if errors.As(err, &missing) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("deleting note from table %s: %w", s.table, err)
	}
	return nil
}
