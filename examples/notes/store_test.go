// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func TestNoteItemRoundTrips(t *testing.T) {
	created := time.Date(2026, 9, 27, 12, 0, 0, 5, time.UTC)
	n := Note{ID: "00000000000000000001-abcd", Text: "hello", CreatedAt: created}
	item := noteItem("a@example.com", n)
	if pk := item[attrPK].(*types.AttributeValueMemberS).Value; pk != "USER#a@example.com" {
		t.Fatalf("pk = %q", pk)
	}
	if sk := item[attrSK].(*types.AttributeValueMemberS).Value; sk != "NOTE#"+n.ID {
		t.Fatalf("sk = %q", sk)
	}
	got, err := noteFromItem(item)
	if err != nil || got != n {
		t.Fatalf("round trip = %+v, %v; want %+v", got, err, n)
	}
}

func TestNoteFromItemRejectsMalformedItems(t *testing.T) {
	good := noteItem("a@example.com", Note{ID: "x", Text: "t", CreatedAt: time.Now().UTC()})
	for _, attr := range []string{attrSK, attrText, attrCreatedAt} {
		item := map[string]types.AttributeValue{}
		for k, v := range good {
			item[k] = v
		}
		delete(item, attr)
		if _, err := noteFromItem(item); err == nil {
			t.Errorf("item without %s was accepted", attr)
		}
	}
	good[attrCreatedAt] = &types.AttributeValueMemberS{Value: "yesterday"}
	if _, err := noteFromItem(good); err == nil {
		t.Error("unparseable createdAt was accepted")
	}
}

func TestNoteIDsSortInCreationOrder(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	earlier, err := newNoteID(base)
	if err != nil {
		t.Fatal(err)
	}
	later, err := newNoteID(base.Add(time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	same, err := newNoteID(base)
	if err != nil {
		t.Fatal(err)
	}
	if earlier >= later {
		t.Fatalf("%q does not sort before %q", earlier, later)
	}
	if earlier == same {
		t.Fatal("two IDs for the same instant collided")
	}
}
