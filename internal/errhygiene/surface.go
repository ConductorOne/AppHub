// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package errhygiene

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// renderingMethods are the method names through which a value's contents reach
// text. A type with any of them can put what it holds into an error, a log line or
// a wire format, so each has to be exercised by some driver.
var renderingMethods = map[string]bool{
	"Error":       true,
	"String":      true,
	"GoString":    true,
	"Format":      true,
	"LogValue":    true,
	"MarshalJSON": true,
	"MarshalText": true,
	"GobEncode":   true,
}

// category records how an exported callable is reachable. It exists because the
// first version of this derivation had exactly one category -- a syntactic
// FuncDecl -- and review defeated it twice by using a shape that is not one.
type category string

const (
	catFunc      category = "package function"
	catFuncVar   category = "exported var of func type"
	catMethod    category = "method in an exported type's method set"
	catInterface category = "method of an exported interface"
	catField     category = "exported struct field of func type"
)

// entryPoint is an exported callable that takes at least one argument.
//
// Taking an argument is the whole filter, and it is deliberately cruder than
// "takes a string": foreign text reached three of the four inputs review first
// found through something other than a string parameter -- an interface whose
// method returns one, a struct field, a byte slice. Classifying which parameter
// types can carry text would be a second hand-maintained restatement, and the
// Granter port list on this project has already shown what those do.
//
// Zero-argument callables are not entry points because they introduce no new text:
// they can only render what the receiver already holds, and the receiver was built
// by something that is an entry point. That is not taken on faith -- see the
// RenderersExercised and TextProducersInvoked checks, and the Accounting check
// which requires the two counts to add up to the type checker's own total.
type entryPoint struct {
	Key      string // "credentials.(*ProviderRegistry).Register"
	Category category
	Params   int
	Where    string // file:line, so a missing driver names something findable
}

// renderer is an exported type with at least one rendering method in its method
// set. Promotion is included, because the method set is the type checker's and not
// a scan of declarations.
type renderer struct {
	Key     string // "credentials.Secret"
	Methods []string
}

type surface struct {
	// Pkg is the type checker's own name for the package, which is what every key
	// below is prefixed with.
	Pkg     string
	Entries map[string]entryPoint

	// Parameterless is every exported callable taking no arguments. It is split
	// because "takes no arguments" is not the same as "cannot leak": a
	// parameterless method renders what its receiver already holds, and review
	// escaped an earlier version of this fixture with a zero-argument
	// Foreign.Reveal that text/template called by name. TextProducers is the half
	// that can become text and must therefore be exercised; the rest return only
	// bools and numbers.
	Parameterless map[string]category
	TextProducers map[string]string // key -> "pkg.Type"
	Renderers     map[string]renderer

	// promotedFields is how many func-typed fields recordFields found through an
	// embedded type. They have no declaration on the owning type, so the
	// independent recount above cannot see them and the Accounting check adds them
	// back rather than tolerating a mismatch.
	promotedFields int

	// deepEmbedding records that recordFields hit its depth bound, so a bound that
	// was reached is reported rather than silently obeyed.
	deepEmbedding bool

	// pkg is the type-checked package, kept so the Accounting check can recount
	// the exported callables by its own traversal.
	pkg *types.Package
}

// derived caches one package's derivation. Type-checking from source is the
// expensive part and several checks want the same answer.
var derived sync.Map // import path -> *derivation

type derivation struct {
	once    sync.Once
	surface surface
	err     error
}

// derive type-checks one package and asks the type checker what it exports.
//
// It does not parse declarations. The first version did, and its notion of "the
// exported surface" was syntax: it saw only *ast.FuncDecl, so it missed every
// method of an exported interface, and review defeated it with two shapes that are
// exported API and are not FuncDecls -- an exported var of func type, and a method
// promoted into an exported type from an unexported embedded one. It reported 33 of
// a real 37 and nothing reconciled the two numbers.
//
// go/types closes that gap: Package.Scope is the answer to "what is exported", and
// types.NewMethodSet is the answer to "what methods does this type have", with
// promotion resolved by the type checker rather than by this file.
//
// It does not close every gap, and an earlier version of this comment claimed it
// did "by construction". Review falsified that twice over. go/importer type-checks
// ONE build configuration, so a file behind a build constraint this configuration
// does not satisfy is invisible here and is still exported API -- see
// [Subject.assertPopulation], which obtains the population a different way for
// exactly that reason. And types.Struct.Field reports declared fields only, so a
// func-typed field promoted through an embedded struct needed recordFields to walk
// for it. **The configuration you type-check in is itself a population choice**,
// which is the general form: go/types is necessary and not sufficient.
func derive(importPath string) (surface, error) {
	v, _ := derived.LoadOrStore(importPath, &derivation{})
	d, ok := v.(*derivation)
	if !ok {
		return surface{}, fmt.Errorf("errhygiene: derivation cache holds a %T", v)
	}
	d.once.Do(func() { d.surface, d.err = deriveOnce(importPath) })
	return d.surface, d.err
}

func deriveOnce(importPath string) (surface, error) {
	// go/importer's source compiler type-checks from source with nothing outside
	// the standard library, so this needs no new module dependency and no build.
	fset := token.NewFileSet()
	pkg, err := importer.ForCompiler(fset, "source", nil).Import(importPath)
	if err != nil {
		return surface{}, fmt.Errorf("type-check %s: %w", importPath, err)
	}

	pos := func(o types.Object) string {
		p := fset.Position(o.Pos())
		if p.Filename == "" {
			return "position unknown"
		}
		return fmt.Sprintf("%s:%d", filepath.Base(p.Filename), p.Line)
	}

	s := surface{
		Pkg:           pkg.Name(),
		pkg:           pkg,
		Entries:       map[string]entryPoint{},
		Parameterless: map[string]category{},
		TextProducers: map[string]string{},
		Renderers:     map[string]renderer{},
	}

	name := s.Pkg
	scope := pkg.Scope()
	for _, objName := range scope.Names() {
		obj := scope.Lookup(objName)
		if !obj.Exported() {
			continue
		}
		switch o := obj.(type) {
		case *types.Func:
			s.record(name+"."+o.Name(), catFunc, o.Signature(), pos(o))

		case *types.Var:
			// An exported package-level var whose type is a function is an
			// exported input: a caller calls it. This is one of the two shapes that
			// defeated the syntactic derivation.
			if sig, ok := o.Type().Underlying().(*types.Signature); ok {
				s.record(name+"."+o.Name(), catFuncVar, sig, pos(o))
			}

		case *types.TypeName:
			named, ok := o.Type().(*types.Named)
			if !ok {
				continue
			}
			if iface, ok := named.Underlying().(*types.Interface); ok {
				for j := range iface.NumMethods() {
					m := iface.Method(j)
					if !m.Exported() {
						continue
					}
					key := fmt.Sprintf("%s.(%s).%s", name, o.Name(), m.Name())
					s.record(key, catInterface, m.Signature(), pos(m))
				}
				continue
			}
			s.recordMethodSet(name, o.Name(), named, pos)
			if st, ok := named.Underlying().(*types.Struct); ok {
				s.recordFields(name, o.Name(), st, 0, map[string]bool{}, pos)
			}
		}
	}
	return s, nil
}

// countExportedCallables recomputes the type checker's own total, by its own
// traversal.
//
// This is the check the count 33-of-37 would have failed, and it is deliberately a
// second traversal rather than a counter incremented inside the first. A counter
// kept by deriveOnce would drop in step with any narrowing of deriveOnce, so a
// derivation that stopped visiting interfaces would report a smaller total and a
// smaller filing and agree with itself. Two traversals cannot.
//
// It counts *declared* func-typed struct fields only -- no promotion -- because
// recordFields does walk promotion, so a promoted field makes the filing exceed
// this total. surface.promotedFields is what reconciles the two, and it is counted
// where promotion actually happens rather than guessed at here.
func countExportedCallables(pkg *types.Package) int {
	total := 0
	scope := pkg.Scope()
	for _, objName := range scope.Names() {
		obj := scope.Lookup(objName)
		if !obj.Exported() {
			continue
		}
		switch o := obj.(type) {
		case *types.Func:
			total++
		case *types.Var:
			if _, ok := o.Type().Underlying().(*types.Signature); ok {
				total++
			}
		case *types.TypeName:
			named, ok := o.Type().(*types.Named)
			if !ok {
				continue
			}
			if iface, ok := named.Underlying().(*types.Interface); ok {
				for j := range iface.NumMethods() {
					if iface.Method(j).Exported() {
						total++
					}
				}
				continue
			}
			ms := types.NewMethodSet(types.NewPointer(named))
			for j := range ms.Len() {
				if fn, ok := ms.At(j).Obj().(*types.Func); ok && fn.Exported() {
					total++
				}
			}
			if st, ok := named.Underlying().(*types.Struct); ok {
				for j := range st.NumFields() {
					f := st.Field(j)
					if !f.Exported() {
						continue
					}
					if _, ok := f.Type().Underlying().(*types.Signature); ok {
						total++
					}
				}
			}
		}
	}
	return total
}

// record files one exported callable as an entry point or as parameterless.
// Everything exported and callable lands in exactly one of the two, which is what
// makes the accounting check possible.
func (s *surface) record(key string, cat category, sig *types.Signature, where string) {
	if sig.Params().Len() == 0 {
		s.Parameterless[key] = cat
		if cat == catMethod && canProduceText(sig) {
			if owner := keyOwner(key); owner != "" {
				s.TextProducers[key] = owner
			}
		}
		return
	}
	s.Entries[key] = entryPoint{Key: key, Category: cat, Params: sig.Params().Len(), Where: where}
}

// canProduceText reports whether any result of sig could carry text.
//
// Anything that is not a bool or a number is assumed to, which is deliberately
// crude for the same reason the entry-point filter is: classifying precisely which
// result types can carry text would be a hand-maintained restatement, and the blind
// spot review exploited here was a hard-coded list of eight method names.
func canProduceText(sig *types.Signature) bool {
	for i := range sig.Results().Len() {
		b, ok := sig.Results().At(i).Type().Underlying().(*types.Basic)
		if !ok {
			return true
		}
		if b.Info()&(types.IsBoolean|types.IsNumeric) == 0 {
			return true
		}
	}
	return false
}

// recordMethodSet walks the full method set of a named type.
//
// The pointer method set is used because it is a superset of the value method set,
// so one pass sees every method. Which of the two a method belongs to only decides
// how the key is spelled, matching the receiver a caller would write.
func (s *surface) recordMethodSet(pkg, typeName string, named *types.Named, pos func(types.Object) string) {
	valueSet := map[string]bool{}
	vms := types.NewMethodSet(named)
	for i := range vms.Len() {
		valueSet[vms.At(i).Obj().Name()] = true
	}

	var rendering []string
	pms := types.NewMethodSet(types.NewPointer(named))
	for i := range pms.Len() {
		fn, ok := pms.At(i).Obj().(*types.Func)
		if !ok || !fn.Exported() {
			continue
		}
		star := "*"
		if valueSet[fn.Name()] {
			star = ""
		}
		key := fmt.Sprintf("%s.(%s%s).%s", pkg, star, typeName, fn.Name())
		s.record(key, catMethod, fn.Signature(), pos(fn))
		if renderingMethods[fn.Name()] {
			rendering = append(rendering, fn.Name())
		}
	}
	if len(rendering) > 0 {
		sort.Strings(rendering)
		s.Renderers[pkg+"."+typeName] = renderer{Key: pkg + "." + typeName, Methods: rendering}
	}
}

// recordFields walks a struct's field set including fields promoted through
// embedded types.
//
// types.Struct.Field reports only *declared* fields, so an embedded struct
// contributes one field -- itself -- and not the fields a caller can actually
// select through it. Review escaped an earlier version of this fixture with an
// exported func-typed field on an unexported embedded struct: `v.Input(sentinel)`
// compiles and returns caller text, and the derivation counted only the
// constructor. Selector depth decides shadowing, so the shallowest name wins and
// deeper ones are skipped, which is Go's rule.
//
// The depth bound is stated rather than implied: eight levels of embedding, and a
// deeper one is not silently ignored -- assertDerivation reports the bound being
// reached.
func (s *surface) recordFields(pkg, typeName string, st *types.Struct, depth int, seen map[string]bool, pos func(types.Object) string) {
	if depth > maxEmbedDepth {
		s.deepEmbedding = true
		return
	}
	var embedded []*types.Struct
	for i := range st.NumFields() {
		f := st.Field(i)
		if f.Embedded() {
			if inner := structUnder(f.Type()); inner != nil {
				embedded = append(embedded, inner)
			}
			continue
		}
		if !f.Exported() || seen[f.Name()] {
			continue
		}
		seen[f.Name()] = true
		if sig, ok := f.Type().Underlying().(*types.Signature); ok {
			s.record(fmt.Sprintf("%s.%s.%s", pkg, typeName, f.Name()), catField, sig, pos(f))
			if depth > 0 {
				s.promotedFields++
			}
		}
	}
	// Breadth first, so a shallower field shadows a deeper one as Go does.
	for _, inner := range embedded {
		s.recordFields(pkg, typeName, inner, depth+1, seen, pos)
	}
}

// maxEmbedDepth bounds recordFields. A bound that is reached is reported, because
// "there was nothing deeper" and "I stopped looking" are different facts and only
// one of them is safe to build an invariant on.
const maxEmbedDepth = 8

// structUnder returns the struct a (possibly pointer) type resolves to, or nil.
func structUnder(t types.Type) *types.Struct {
	if p, ok := t.Underlying().(*types.Pointer); ok {
		t = p.Elem()
	}
	st, _ := t.Underlying().(*types.Struct)
	return st
}

// receiverType returns an AST method's receiver base type name and whether it is a
// pointer. Only the syntax sweep needs this; the derivation gets receivers from the
// type checker.
func receiverType(fd *ast.FuncDecl) (string, bool, bool) {
	if fd.Recv == nil || len(fd.Recv.List) != 1 {
		return "", false, false
	}
	expr := fd.Recv.List[0].Type
	ptr := false
	if star, ok := expr.(*ast.StarExpr); ok {
		ptr = true
		expr = star.X
	}
	switch e := expr.(type) {
	case *ast.IndexExpr:
		expr = e.X
	case *ast.IndexListExpr:
		expr = e.X
	}
	id, ok := expr.(*ast.Ident)
	if !ok {
		return "", ptr, false
	}
	return id.Name, ptr, true
}

// buildTags renders a file's build constraints for a failure message.
func buildTags(f *ast.File) string {
	var out []string
	for _, g := range f.Comments {
		for _, c := range g.List {
			if strings.HasPrefix(c.Text, "//go:build") {
				out = append(out, strings.TrimSpace(strings.TrimPrefix(c.Text, "//go:build")))
			}
		}
	}
	if len(out) == 0 {
		return ""
	}
	return " (build " + strings.Join(out, " ") + ")"
}

// declaredKeys returns the derivation keys a syntax declaration should produce.
//
// Only the shapes the derivation can also name: package functions, methods on
// exported receivers, exported func-typed vars, exported types with rendering
// methods, exported interfaces and their methods, and exported func-typed struct
// fields wherever they are declared -- including inside an unexported struct,
// because that is how a promoted field reaches an exported type.
func declaredKeys(pkg string, decl ast.Decl) [][]string {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		if !d.Name.IsExported() {
			return nil
		}
		if d.Recv == nil {
			return [][]string{{pkg + "." + d.Name.Name}}
		}
		recv, _, ok := receiverType(d)
		if !ok || !ast.IsExported(recv) {
			return nil
		}
		// Both spellings, because whether a method lands in the value or the
		// pointer method set is the type checker's answer and not this sweep's.
		return [][]string{{
			fmt.Sprintf("%s.(%s).%s", pkg, recv, d.Name.Name),
			fmt.Sprintf("%s.(*%s).%s", pkg, recv, d.Name.Name),
		}}
	case *ast.GenDecl:
		var out [][]string
		for _, spec := range d.Specs {
			switch sp := spec.(type) {
			case *ast.ValueSpec:
				if d.Tok != token.VAR {
					continue
				}
				for _, n := range sp.Names {
					if n.IsExported() && isFuncType(sp.Type) {
						out = append(out, []string{pkg + "." + n.Name})
					}
				}
			case *ast.TypeSpec:
				out = append(out, declaredTypeKeys(pkg, sp)...)
			}
		}
		return out
	}
	return nil
}

// declaredTypeKeys returns the keys a type declaration should produce: its
// interface methods, and its func-typed fields.
func declaredTypeKeys(pkg string, sp *ast.TypeSpec) [][]string {
	var out [][]string
	switch t := sp.Type.(type) {
	case *ast.InterfaceType:
		// An exported interface's methods are exported API with no declaration of
		// their own beyond this one, and they were invisible to the first,
		// syntactic derivation.
		if !sp.Name.IsExported() || t.Methods == nil {
			return nil
		}
		for _, m := range t.Methods.List {
			for _, n := range m.Names {
				if n.IsExported() {
					out = append(out, []string{fmt.Sprintf("%s.(%s).%s", pkg, sp.Name.Name, n.Name)})
				}
			}
		}
	case *ast.StructType:
		if t.Fields == nil {
			return nil
		}
		for _, field := range t.Fields.List {
			if !isFuncType(field.Type) {
				continue
			}
			for _, n := range field.Names {
				if !n.IsExported() {
					continue
				}
				// The field may be promoted into any exported type that embeds
				// this one, so the owner is a wildcard: the derivation names the
				// outer type and this sweep cannot know it.
				out = append(out, []string{pkg + ".*." + n.Name})
			}
		}
	}
	return out
}

// anyKnown reports whether any spelling of a declaration is in the derived set. A
// key of the form "pkg.*.Field" matches any owner, because a promoted field's owner
// is the type checker's answer and not the sweep's.
func anyKnown(known map[string]bool, alts []string) bool {
	for _, k := range alts {
		if known[k] {
			return true
		}
		if mid := strings.Index(k, ".*."); mid >= 0 {
			prefix, suffix := k[:mid+1], k[mid+2:]
			for have := range known {
				if strings.HasPrefix(have, prefix) && strings.HasSuffix(have, suffix) {
					return true
				}
			}
		}
	}
	return false
}

// isFuncType reports whether an expression is a function type.
func isFuncType(e ast.Expr) bool {
	_, ok := e.(*ast.FuncType)
	return ok
}

// sweep parses every Go file in dir with no build constraints applied at all, and
// returns the keys each declaration should have produced.
func sweep(dir string) (files int, decls [][]string, tags map[string]string, err error) {
	names, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return 0, nil, nil, fmt.Errorf("glob %s: %w", dir, err)
	}
	tags = map[string]string{}
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		// ParseFile applies no build constraints, which is the whole point.
		f, perr := parser.ParseFile(fset, name, nil, parser.ParseComments|parser.SkipObjectResolution)
		if perr != nil {
			return 0, nil, nil, fmt.Errorf("parse %s: %w", name, perr)
		}
		files++
		for _, decl := range f.Decls {
			for _, alts := range declaredKeys(f.Name.Name, decl) {
				decls = append(decls, alts)
				tags[alts[0]] = filepath.Base(name) + buildTags(f)
			}
		}
	}
	return files, decls, tags, nil
}
