// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// fakeDynamo is an in-memory stand-in for the DynamoDB operations this package
// calls, including an evaluator for the expression strings it writes.
//
// It exists because the alternative is not testing the fence at all. The
// interesting content of store is exactly the part a mock cannot check: whether
// "attribute_exists(PK) AND Revision = :rev" means what the code assumes, whether
// a filter expression admits a record with no expiry, whether a paginated Scan
// that returns an empty page with a LastEvaluatedKey is handled. A double that
// merely records calls would let all of those through, and a real table would
// make the suite non-hermetic.
//
// It is not a DynamoDB emulator. It implements the operators this package
// actually uses -- and it fails loudly on anything it does not recognise, so a
// future query cannot quietly go unverified.
type fakeDynamo struct {
	mu sync.Mutex

	// items is keyed by PK then SK, mirroring the real key structure.
	items map[string]map[string]map[string]types.AttributeValue

	// pageSize caps items per response so the pagination loops get exercised.
	// DynamoDB pages on items *read*, not items matched, so a page can come back
	// empty with a LastEvaluatedKey set -- the case a naive loop mishandles.
	pageSize int

	// tableName is asserted on every call: an operation aimed at the wrong table
	// is a bug this double should catch rather than absorb.
	tableName      string
	auditTableName string

	// calls counts operations by name, so a test can assert that a query went out
	// as a Query and not as a Scan.
	calls map[string]int
}

func newFakeDynamo(tableName string) *fakeDynamo {
	return &fakeDynamo{
		items:     make(map[string]map[string]map[string]types.AttributeValue),
		pageSize:  2,
		tableName: tableName,
		calls:     make(map[string]int),
	}
}

func (f *fakeDynamo) callCount(op string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[op]
}

func (f *fakeDynamo) record(op string, table *string) error {
	f.calls[op]++
	if table == nil || (*table != f.tableName && *table != f.auditTableName) {
		return fmt.Errorf("fakeDynamo: %s aimed at table %v, want %q or %q", op, table, f.tableName, f.auditTableName)
	}
	return nil
}

func (f *fakeDynamo) PutItem(_ context.Context, in *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("PutItem", in.TableName); err != nil {
		return nil, err
	}

	pk, sk, err := keyOf(in.Item)
	if err != nil {
		return nil, err
	}
	existing := f.items[pk][sk]

	if in.ConditionExpression != nil {
		ok, err := evalExpression(*in.ConditionExpression, existing, in.ExpressionAttributeNames, in.ExpressionAttributeValues)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, conditionalFailure(existing, in.ReturnValuesOnConditionCheckFailure)
		}
	}

	if f.items[pk] == nil {
		f.items[pk] = make(map[string]map[string]types.AttributeValue)
	}
	f.items[pk][sk] = copyItem(in.Item)
	return &dynamodb.PutItemOutput{}, nil
}

func (f *fakeDynamo) GetItem(_ context.Context, in *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("GetItem", in.TableName); err != nil {
		return nil, err
	}

	pk, sk, err := keyOf(in.Key)
	if err != nil {
		return nil, err
	}
	// A miss is an empty Item, not an error -- the behaviour the source's
	// (nil, nil) return was built on.
	return &dynamodb.GetItemOutput{Item: copyItem(f.items[pk][sk])}, nil
}

func (f *fakeDynamo) DeleteItem(_ context.Context, in *dynamodb.DeleteItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("DeleteItem", in.TableName); err != nil {
		return nil, err
	}

	pk, sk, err := keyOf(in.Key)
	if err != nil {
		return nil, err
	}
	existing := f.items[pk][sk]

	if in.ConditionExpression != nil {
		ok, err := evalExpression(*in.ConditionExpression, existing, in.ExpressionAttributeNames, in.ExpressionAttributeValues)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, conditionalFailure(existing, in.ReturnValuesOnConditionCheckFailure)
		}
	}

	delete(f.items[pk], sk)
	return &dynamodb.DeleteItemOutput{}, nil
}

func (f *fakeDynamo) Query(_ context.Context, in *dynamodb.QueryInput, _ ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("Query", in.TableName); err != nil {
		return nil, err
	}
	if in.IndexName != nil && *in.IndexName != indexGSI1 {
		return nil, fmt.Errorf("fakeDynamo: Query on unsupported index %v", in.IndexName)
	}
	if in.IndexName != nil && aws.ToBool(in.ConsistentRead) {
		return nil, fmt.Errorf("fakeDynamo: GSI does not support consistent reads")
	}
	if in.KeyConditionExpression == nil {
		return nil, fmt.Errorf("fakeDynamo: Query without a KeyConditionExpression")
	}

	// A Query reads only the keys matching its condition, so unlike Scan the
	// filtering happens before paging.
	var matched []map[string]types.AttributeValue
	for _, item := range f.all() {
		ok, err := evalExpression(*in.KeyConditionExpression, item, in.ExpressionAttributeNames, in.ExpressionAttributeValues)
		if err != nil {
			return nil, err
		}
		if ok {
			matched = append(matched, item)
		}
	}

	// A cursor is an ordering boundary, not a reference that must still exist:
	// TTL/deletion or a queue transition may remove its row between pages.
	sortKey := attrSK
	if in.IndexName != nil {
		sortKey = "GSI1SK"
	}
	compare := func(a, b map[string]types.AttributeValue) int {
		for _, key := range []string{sortKey, attrPK, attrSK} {
			if order := strings.Compare(stringAttr(a, key), stringAttr(b, key)); order != 0 {
				if in.ScanIndexForward != nil && !*in.ScanIndexForward {
					return -order
				}
				return order
			}
		}
		return 0
	}
	sort.Slice(matched, func(i, j int) bool { return compare(matched[i], matched[j]) < 0 })
	if len(in.ExclusiveStartKey) != 0 {
		start := sort.Search(len(matched), func(i int) bool { return compare(matched[i], in.ExclusiveStartKey) > 0 })
		matched = matched[start:]
	}
	size := f.pageSize
	if in.Limit != nil {
		if *in.Limit <= 0 {
			return nil, fmt.Errorf("fakeDynamo: invalid Query limit")
		}
		size = min(size, int(*in.Limit))
	}
	page := matched[:min(size, len(matched))]
	var last map[string]types.AttributeValue
	if len(page) < len(matched) {
		lastItem := page[len(page)-1]
		last = map[string]types.AttributeValue{attrPK: lastItem[attrPK], attrSK: lastItem[attrSK]}
	}
	if len(last) != 0 && in.IndexName != nil {
		lastItem := page[len(page)-1]
		last["GSI1PK"], last["GSI1SK"] = lastItem["GSI1PK"], lastItem["GSI1SK"]
	}
	return &dynamodb.QueryOutput{Items: page, LastEvaluatedKey: last}, nil
}

func (f *fakeDynamo) Scan(_ context.Context, in *dynamodb.ScanInput, _ ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("Scan", in.TableName); err != nil {
		return nil, err
	}

	// Page over every item in key order, then filter what the page read. This is
	// the DynamoDB ordering and it matters: a page whose items are all filtered
	// out still advances LastEvaluatedKey, so a caller that stops at the first
	// empty page silently truncates its results.
	scanned, last := f.paginate(f.all(), in.ExclusiveStartKey)

	var matched []map[string]types.AttributeValue
	for _, item := range scanned {
		if in.FilterExpression == nil {
			matched = append(matched, item)
			continue
		}
		ok, err := evalExpression(*in.FilterExpression, item, in.ExpressionAttributeNames, in.ExpressionAttributeValues)
		if err != nil {
			return nil, err
		}
		if ok {
			matched = append(matched, item)
		}
	}
	return &dynamodb.ScanOutput{Items: matched, LastEvaluatedKey: last}, nil
}

// all returns every stored item in a deterministic key order.
func (f *fakeDynamo) all() []map[string]types.AttributeValue {
	var out []map[string]types.AttributeValue
	pks := make([]string, 0, len(f.items))
	for pk := range f.items {
		pks = append(pks, pk)
	}
	sort.Strings(pks)
	for _, pk := range pks {
		sks := make([]string, 0, len(f.items[pk]))
		for sk := range f.items[pk] {
			sks = append(sks, sk)
		}
		sort.Strings(sks)
		for _, sk := range sks {
			out = append(out, copyItem(f.items[pk][sk]))
		}
	}
	return out
}

// paginate returns one page of ordered and the key to resume after, or nil when
// the page is the last.
func (f *fakeDynamo) paginate(ordered []map[string]types.AttributeValue, startKey map[string]types.AttributeValue) ([]map[string]types.AttributeValue, map[string]types.AttributeValue) {
	start := 0
	if len(startKey) > 0 {
		pk, sk, err := keyOf(startKey)
		if err == nil {
			for i, item := range ordered {
				if stringAttr(item, attrPK) == pk && stringAttr(item, attrSK) == sk {
					start = i + 1
					break
				}
			}
		}
	}
	if start >= len(ordered) {
		return nil, nil
	}

	end := min(start+f.pageSize, len(ordered))
	page := ordered[start:end]
	if end == len(ordered) {
		return page, nil
	}
	lastItem := ordered[end-1]
	return page, map[string]types.AttributeValue{
		attrPK: &types.AttributeValueMemberS{Value: stringAttr(lastItem, attrPK)},
		attrSK: &types.AttributeValueMemberS{Value: stringAttr(lastItem, attrSK)},
	}
}

func conditionalFailure(existing map[string]types.AttributeValue, ret types.ReturnValuesOnConditionCheckFailure) error {
	err := &types.ConditionalCheckFailedException{
		Message: aws.String("The conditional request failed"),
	}
	// Only ALL_OLD returns the item, which is what makes "gone" and "someone
	// wrote first" distinguishable at the call site.
	if ret == types.ReturnValuesOnConditionCheckFailureAllOld {
		err.Item = copyItem(existing)
	}
	return err
}

func keyOf(item map[string]types.AttributeValue) (string, string, error) {
	pk, pkOK := item[attrPK].(*types.AttributeValueMemberS)
	sk, skOK := item[attrSK].(*types.AttributeValueMemberS)
	if !pkOK || !skOK {
		return "", "", fmt.Errorf("fakeDynamo: item is missing string %s/%s", attrPK, attrSK)
	}
	return pk.Value, sk.Value, nil
}

func copyItem(item map[string]types.AttributeValue) map[string]types.AttributeValue {
	if item == nil {
		return nil
	}
	out := make(map[string]types.AttributeValue, len(item))
	for k, v := range item {
		out[k] = v
	}
	return out
}

func stringAttr(item map[string]types.AttributeValue, name string) string {
	if s, ok := item[name].(*types.AttributeValueMemberS); ok {
		return s.Value
	}
	return ""
}

// evalExpression evaluates one of this package's expression strings against an
// item. item is nil when the item does not exist, which is how
// attribute_not_exists succeeds.
//
// Only AND-joined clauses are supported because that is all this package writes.
// Anything else is an error rather than a false: a silently-mis-evaluated
// condition expression is precisely the bug class this double exists to catch.
func evalExpression(expr string, item map[string]types.AttributeValue, names map[string]string, values map[string]types.AttributeValue) (bool, error) {
	if strings.Contains(expr, " OR ") || strings.Contains(expr, "NOT ") {
		return false, fmt.Errorf("fakeDynamo: unsupported expression %q", expr)
	}
	for _, clause := range strings.Split(expr, " AND ") {
		ok, err := evalClause(strings.TrimSpace(clause), item, names, values)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

func evalClause(clause string, item map[string]types.AttributeValue, names map[string]string, values map[string]types.AttributeValue) (bool, error) {
	resolve := func(name string) string {
		if strings.HasPrefix(name, "#") {
			return names[name]
		}
		return name
	}

	if inner, ok := fnArg(clause, "attribute_not_exists"); ok {
		_, present := item[resolve(inner)]
		return !present, nil
	}
	if inner, ok := fnArg(clause, "attribute_exists"); ok {
		_, present := item[resolve(inner)]
		return present, nil
	}
	if inner, ok := fnArg(clause, "begins_with"); ok {
		parts := strings.SplitN(inner, ",", 2)
		if len(parts) != 2 {
			return false, fmt.Errorf("fakeDynamo: malformed begins_with %q", clause)
		}
		got := item[resolve(strings.TrimSpace(parts[0]))]
		want, ok := values[strings.TrimSpace(parts[1])]
		if !ok {
			return false, fmt.Errorf("fakeDynamo: begins_with references undefined value in %q", clause)
		}
		return strings.HasPrefix(attrString(got), attrString(want)), nil
	}

	// Comparators, longest operator first so "<=" is not read as "<".
	for _, op := range []string{"<>", "<=", ">=", "=", "<", ">"} {
		lhs, rhs, found := cut(clause, " "+op+" ")
		if !found {
			continue
		}
		got, present := item[resolve(strings.TrimSpace(lhs))]
		want, ok := values[strings.TrimSpace(rhs)]
		if !ok {
			return false, fmt.Errorf("fakeDynamo: clause %q references an undefined value", clause)
		}
		// DynamoDB treats a comparison against a missing attribute as false, and
		// <> against a missing attribute as false too -- the attribute has to exist
		// to be unequal to something.
		if !present {
			return false, nil
		}
		cmp, err := compareAttrs(got, want)
		if err != nil {
			return false, fmt.Errorf("fakeDynamo: clause %q: %w", clause, err)
		}
		switch op {
		case "=":
			return cmp == 0, nil
		case "<>":
			return cmp != 0, nil
		case "<":
			return cmp < 0, nil
		case "<=":
			return cmp <= 0, nil
		case ">":
			return cmp > 0, nil
		case ">=":
			return cmp >= 0, nil
		}
	}

	return false, fmt.Errorf("fakeDynamo: unsupported clause %q", clause)
}

// fnArg returns the argument text of a function-call clause.
func fnArg(clause, fn string) (string, bool) {
	prefix := fn + "("
	if !strings.HasPrefix(clause, prefix) || !strings.HasSuffix(clause, ")") {
		return "", false
	}
	return clause[len(prefix) : len(clause)-1], true
}

func cut(s, sep string) (string, string, bool) {
	i := strings.Index(s, sep)
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+len(sep):], true
}

// compareAttrs orders two attribute values the way DynamoDB does: numbers
// numerically, strings bytewise. Mixing the two is a type error rather than a
// silent false, because comparing an N against an S is always a bug in the query.
func compareAttrs(a, b types.AttributeValue) (int, error) {
	switch av := a.(type) {
	case *types.AttributeValueMemberS:
		bv, ok := b.(*types.AttributeValueMemberS)
		if !ok {
			return 0, fmt.Errorf("cannot compare S with %T", b)
		}
		return strings.Compare(av.Value, bv.Value), nil
	case *types.AttributeValueMemberN:
		bv, ok := b.(*types.AttributeValueMemberN)
		if !ok {
			return 0, fmt.Errorf("cannot compare N with %T", b)
		}
		an, aOK := new(big.Rat).SetString(av.Value)
		bn, bOK := new(big.Rat).SetString(bv.Value)
		if !aOK || !bOK {
			return 0, fmt.Errorf("invalid numeric attribute")
		}
		return an.Cmp(bn), nil
	case *types.AttributeValueMemberBOOL:
		bv, ok := b.(*types.AttributeValueMemberBOOL)
		if !ok {
			return 0, fmt.Errorf("cannot compare BOOL with %T", b)
		}
		if av.Value == bv.Value {
			return 0, nil
		}
		return 1, nil
	default:
		return 0, fmt.Errorf("unsupported attribute type %T", a)
	}
}

func attrString(v types.AttributeValue) string {
	if s, ok := v.(*types.AttributeValueMemberS); ok {
		return s.Value
	}
	return ""
}

// newTestClient wires a Client onto the double. It bypasses New because New
// loads real AWS configuration.
func newTestClient(f *fakeDynamo) *Client {
	return &Client{api: f, tableName: f.tableName}
}

// Updates are evaluated against a copy: an invalid expression or lost condition
// cannot leave an earlier assignment visible.
func (f *fakeDynamo) UpdateItem(_ context.Context, in *dynamodb.UpdateItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("UpdateItem", in.TableName); err != nil {
		return nil, err
	}
	pk, sk, err := keyOf(in.Key)
	if err != nil {
		return nil, err
	}
	existing := f.items[pk][sk]
	if in.ConditionExpression != nil {
		ok, err := evalExpression(*in.ConditionExpression, existing, in.ExpressionAttributeNames, in.ExpressionAttributeValues)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, conditionalFailure(existing, in.ReturnValuesOnConditionCheckFailure)
		}
	}
	item := copyItem(existing)
	if item == nil {
		item = copyItem(in.Key)
	}
	resolve := func(name string) string {
		name = strings.TrimSpace(name)
		if strings.HasPrefix(name, "#") {
			return in.ExpressionAttributeNames[name]
		}
		return name
	}
	expression := strings.TrimSpace(aws.ToString(in.UpdateExpression))
	if expression == "" {
		return nil, fmt.Errorf("fakeDynamo: missing update expression")
	}
	var set, remove string
	if strings.HasPrefix(expression, "REMOVE ") {
		set, remove = "", strings.TrimPrefix(expression, "REMOVE ")
	} else {
		set, remove, _ = strings.Cut(expression, " REMOVE ")
		if !strings.HasPrefix(set, "SET ") {
			return nil, fmt.Errorf("fakeDynamo: unsupported update expression %q", expression)
		}
		set = strings.TrimPrefix(set, "SET ")
	}
	for _, assignment := range strings.Split(set, ",") {
		if set == "" {
			break
		}
		name, value, ok := strings.Cut(assignment, "=")
		name, value = resolve(name), strings.TrimSpace(value)
		if !ok || name == "" || name == attrPK || name == attrSK {
			return nil, fmt.Errorf("fakeDynamo: invalid assignment %q", assignment)
		}
		attribute, ok := in.ExpressionAttributeValues[value]
		if !ok {
			left, right, plus := strings.Cut(value, " + ")
			if !plus {
				return nil, fmt.Errorf("fakeDynamo: unsupported update value %q", value)
			}
			a, aOK := item[resolve(left)].(*types.AttributeValueMemberN)
			b, bOK := in.ExpressionAttributeValues[strings.TrimSpace(right)].(*types.AttributeValueMemberN)
			if !aOK || !bOK {
				return nil, fmt.Errorf("fakeDynamo: addition requires numbers")
			}
			an, aOK := new(big.Int).SetString(a.Value, 10)
			bn, bOK := new(big.Int).SetString(b.Value, 10)
			if !aOK || !bOK {
				return nil, fmt.Errorf("fakeDynamo: addition requires integer values")
			}
			attribute = &types.AttributeValueMemberN{Value: an.Add(an, bn).String()}
		}
		item[name] = attribute
	}
	for _, name := range strings.Split(remove, ",") {
		if remove == "" {
			break
		}
		name = resolve(name)
		if name == "" || name == attrPK || name == attrSK {
			return nil, fmt.Errorf("fakeDynamo: invalid removal")
		}
		delete(item, name)
	}
	out := &dynamodb.UpdateItemOutput{}
	switch in.ReturnValues {
	case types.ReturnValueAllOld:
		out.Attributes = copyItem(existing)
	case types.ReturnValueAllNew:
		out.Attributes = copyItem(item)
	case "", types.ReturnValueNone:
	default:
		return nil, fmt.Errorf("fakeDynamo: unsupported update return values")
	}
	if f.items[pk] == nil {
		f.items[pk] = make(map[string]map[string]types.AttributeValue)
	}
	f.items[pk][sk] = item
	return out, nil
}

// Staging under the outer lock gives concurrent callers real all-or-nothing
// semantics. Conditions see the pre-transaction state because duplicate target
// items, including ConditionCheck targets, are rejected just as Dynamo does.
func (f *fakeDynamo) TransactWriteItems(ctx context.Context, in *dynamodb.TransactWriteItemsInput, _ ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls["TransactWriteItems"]++
	if len(in.TransactItems) == 0 || len(in.TransactItems) > 100 {
		return nil, fmt.Errorf("fakeDynamo: invalid transaction length")
	}
	staged := newFakeDynamo(f.tableName)
	staged.auditTableName = f.auditTableName
	for _, item := range f.all() {
		pk, sk, _ := keyOf(item)
		if staged.items[pk] == nil {
			staged.items[pk] = make(map[string]map[string]types.AttributeValue)
		}
		staged.items[pk][sk] = item
	}
	seen := make(map[string]bool)
	for index, operation := range in.TransactItems {
		var key map[string]types.AttributeValue
		count := 0
		if operation.Put != nil {
			key = operation.Put.Item
			count++
		}
		if operation.Delete != nil {
			key = operation.Delete.Key
			count++
		}
		if operation.Update != nil {
			key = operation.Update.Key
			count++
		}
		if operation.ConditionCheck != nil {
			key = operation.ConditionCheck.Key
			count++
		}
		if count != 1 {
			return nil, fmt.Errorf("fakeDynamo: transaction operation must have exactly one action")
		}
		pk, sk, err := keyOf(key)
		if err != nil {
			return nil, err
		}
		identity := pk + "\x00" + sk
		if seen[identity] {
			return nil, fmt.Errorf("fakeDynamo: duplicate transaction target")
		}
		seen[identity] = true
		switch {
		case operation.Put != nil:
			p := operation.Put
			_, err = staged.PutItem(ctx, &dynamodb.PutItemInput{TableName: p.TableName, Item: p.Item, ConditionExpression: p.ConditionExpression, ExpressionAttributeNames: p.ExpressionAttributeNames, ExpressionAttributeValues: p.ExpressionAttributeValues, ReturnValuesOnConditionCheckFailure: p.ReturnValuesOnConditionCheckFailure})
		case operation.Delete != nil:
			d := operation.Delete
			_, err = staged.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: d.TableName, Key: d.Key, ConditionExpression: d.ConditionExpression, ExpressionAttributeNames: d.ExpressionAttributeNames, ExpressionAttributeValues: d.ExpressionAttributeValues, ReturnValuesOnConditionCheckFailure: d.ReturnValuesOnConditionCheckFailure})
		case operation.Update != nil:
			u := operation.Update
			_, err = staged.UpdateItem(ctx, &dynamodb.UpdateItemInput{TableName: u.TableName, Key: u.Key, UpdateExpression: u.UpdateExpression, ConditionExpression: u.ConditionExpression, ExpressionAttributeNames: u.ExpressionAttributeNames, ExpressionAttributeValues: u.ExpressionAttributeValues, ReturnValuesOnConditionCheckFailure: u.ReturnValuesOnConditionCheckFailure})
		case operation.ConditionCheck != nil:
			c := operation.ConditionCheck
			if err = staged.record("ConditionCheck", c.TableName); err == nil {
				var ok bool
				ok, err = evalExpression(aws.ToString(c.ConditionExpression), staged.items[pk][sk], c.ExpressionAttributeNames, c.ExpressionAttributeValues)
				if err == nil && !ok {
					err = conditionalFailure(staged.items[pk][sk], c.ReturnValuesOnConditionCheckFailure)
				}
			}
		}
		if err != nil {
			var conditional *types.ConditionalCheckFailedException
			if errors.As(err, &conditional) {
				reasons := make([]types.CancellationReason, len(in.TransactItems))
				for i := range reasons {
					reasons[i].Code = aws.String("None")
				}
				reasons[index] = types.CancellationReason{Code: aws.String("ConditionalCheckFailed"), Item: conditional.Item}
				return nil, &types.TransactionCanceledException{CancellationReasons: reasons}
			}
			return nil, err
		}
	}
	f.items = staged.items
	return &dynamodb.TransactWriteItemsOutput{}, nil
}
