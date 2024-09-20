// Copyright 2024 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fabridquery

import (
	"fmt"

	"github.com/antlr/antlr4/runtime/Go/antlr"

	"github.com/scionproto/scion/antlr/pathpolicyconstraints"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/experimental/fabrid"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
)

type TypedNumber struct {
	Wildcard bool
	Number   int
}

type ISD TypedNumber

func (i ISD) Matches(ia addr.ISD) bool {
	return i.Wildcard || ia == addr.ISD(i.Number)
}

func (i ISD) String() string {
	if i.Wildcard {
		return "*"
	}
	return fmt.Sprintf("%d", i.Number)

}

type AS struct {
	Wildcard bool
	ASN      addr.AS
}

func (a AS) Matches(iaas addr.AS) bool {
	return a.Wildcard || iaas == a.ASN
}

func (a AS) String() string {
	if a.Wildcard {
		return "*"
	}
	return a.ASN.String()
}

type Interface TypedNumber

func (i Interface) Matches(intf common.IFIDType) bool {
	return i.Wildcard || intf == common.IFIDType(i.Number)
}

func (i Interface) String() string {
	if i.Wildcard {
		return "*"
	}
	return fmt.Sprintf("%d", i.Number)
}

const (
	WILDCARD_POLICY_TYPE = iota
	REJECT_POLICY_TYPE
	STANDARD_POLICY_TYPE
)

type Policy struct {
	Type uint8
	*fabrid.Policy
}

func (p Policy) String() string {
	if p.Type == WILDCARD_POLICY_TYPE {
		return "*"
	} else if p.Type == REJECT_POLICY_TYPE {
		return "reject"
	} else if p.Type == STANDARD_POLICY_TYPE {
		return p.Policy.String()
	}
	return "unknown"
}

type Expressions interface {
	Evaluate([]snet.HopInterface, *MatchList) (bool, *MatchList)
	String() string
}

type Identifier struct {
	Isd    ISD
	As     AS
	IgIntf Interface
	EgIntf Interface
	Policy Policy
}

func (i Identifier) String() string {
	return fmt.Sprintf("{ Isd %s, As %s, IgIntf %s, EgIntf %s, Policy %s }", i.Isd, i.As, i.IgIntf,
		i.EgIntf, i.Policy)
}

func (i Identifier) Evaluate(pi []snet.HopInterface, ml *MatchList) (bool, *MatchList) {
	matched := false
	for idx, p := range pi {
		// Check if ISD, AS and interfaces match between the query and a hop in the path.
		if !(i.Isd.Matches(p.IA.ISD()) && i.As.Matches(p.IA.AS()) && i.IgIntf.Matches(p.IgIf) &&
			i.EgIntf.Matches(p.EgIf)) {
			continue
		}
		// If so and the query sets a wildcard or reject policy, assign this and continue evaluating
		// the query
		if (i.Policy.Type == WILDCARD_POLICY_TYPE && p.FabridEnabled) || i.Policy.
			Type == REJECT_POLICY_TYPE {
			ml.StorePolicy(idx, &i.Policy)
		}

		if i.Policy.Type == WILDCARD_POLICY_TYPE || i.Policy.Type == REJECT_POLICY_TYPE {
			matched = true
			continue
		}
		// Check if the query's policy matches a policy that is available for this hop.
		for _, pol := range p.Policies {
			if pol.Identifier == i.Policy.Identifier && i.Policy.Policy.IsLocal == pol.IsLocal {

				ml.StorePolicy(idx, &Policy{
					Type:   STANDARD_POLICY_TYPE,
					Policy: pol,
				})
				matched = true
			}
		}

	}
	return matched, ml
}

type Expression struct {
	Expressions
}

func (e Expression) Evaluate(pi []snet.HopInterface, ml *MatchList) (bool, *MatchList) {
	return e.Expressions.Evaluate(pi, ml)
}

type Query struct {
	Q Expressions
	T Expressions
	F Expressions
}

func (q Query) String() string {
	return fmt.Sprintf(" Query { Query %s, True %s, False %s } ", q.Q, q.T, q.F)
}

func (q Query) Evaluate(pi []snet.HopInterface, ml *MatchList) (bool, *MatchList) {
	mlOriginal := ml.Copy()
	qRes, _ := q.Q.Evaluate(pi, mlOriginal)
	if qRes {
		return q.T.Evaluate(pi, ml)
	}
	return q.F.Evaluate(pi, ml)
}

type ConcatExpression struct {
	Left  Expressions
	Right Expressions
}

func (e ConcatExpression) String() string {
	return fmt.Sprintf(" Concat { Left %s, Right %s } ", e.Left, e.Right)
}

func (e ConcatExpression) Evaluate(pi []snet.HopInterface, ml *MatchList) (bool, *MatchList) {
	left, mlLeft := e.Left.Evaluate(pi, ml)
	right, mlRight := e.Right.Evaluate(pi, mlLeft)
	return left && right, mlRight
}

type Nop struct{}

func (n Nop) String() string {
	return "Nop"
}

func (n Nop) Evaluate(_ []snet.HopInterface, list *MatchList) (bool, *MatchList) {
	return true, list
}

func ParseFabridQuery(input string) (Expressions, error) {
	istream := antlr.NewInputStream(input)
	lexer := pathpolicyconstraints.NewPathPolicyConstraintsLexer(istream)
	lexer.RemoveErrorListeners()
	errListener := &errorListener{}
	lexer.AddErrorListener(errListener)
	tstream := antlr.NewCommonTokenStream(lexer, antlr.TokenDefaultChannel)
	parser := pathpolicyconstraints.NewPathPolicyConstraintsParser(tstream)
	parser.RemoveErrorListeners()
	parser.AddErrorListener(errListener)
	listener := pathpolicyConstraintsListener{}
	antlr.ParseTreeWalkerDefault.Walk(&listener, parser.Start())
	if errListener.msg != "" || (len(listener.stack) != 1) {
		return nil, serrors.New(errListener.msg)
	}
	expr, ok := listener.stack[0].(Expressions)
	if !ok {
		return nil, serrors.New("Not a valid query")
	}
	return expr, nil
}
