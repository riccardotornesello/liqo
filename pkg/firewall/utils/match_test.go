// Copyright 2019-2025 The Liqo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils_test

import (
	"testing"

	"github.com/google/nftables"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	firewallv1beta1 "github.com/liqotech/liqo/apis/networking/v1beta1/firewall"
	"github.com/liqotech/liqo/pkg/firewall/utils"
)

func TestMatch(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Firewall Match Test Suite")
}

var _ = Describe("Firewall Configuration CtState Tests", func() {
	var (
		conn  *nftables.Conn
		table *nftables.Table
		chain *nftables.Chain
	)

	BeforeEach(func() {
		conn = &nftables.Conn{}
		table = &nftables.Table{
			Name:   "test-table",
			Family: nftables.TableFamilyIPv4,
		}
		chain = &nftables.Chain{
			Name:  "test-chain",
			Table: table,
		}
	})

	Context("When creating filter rules with CtState matching", func() {
		DescribeTable("should correctly handle single ctstate values",
			func(ctStateValue firewallv1beta1.CtStateValue, operation firewallv1beta1.MatchOperation) {
				ruleName := "test-rule"
				actionValue := "1"

				filterRule := &firewallv1beta1.FilterRule{
					Name: &ruleName,
					Match: []firewallv1beta1.Match{
						{
							Op: operation,
							CtState: &firewallv1beta1.MatchCtState{
								Value: []firewallv1beta1.CtStateValue{ctStateValue},
							},
						},
					},
					Action: firewallv1beta1.ActionCtMark,
					Value:  &actionValue,
				}

				wrapper := &utils.FilterRuleWrapper{FilterRule: filterRule}
				err := wrapper.Add(conn, chain)

				Expect(err).NotTo(HaveOccurred())
			},
			Entry("CtStateNew with eq operation", firewallv1beta1.CtStateNew, firewallv1beta1.MatchOperationEq),
			Entry("CtStateEstablished with eq operation", firewallv1beta1.CtStateEstablished, firewallv1beta1.MatchOperationEq),
			Entry("CtStateRelated with eq operation", firewallv1beta1.CtStateRelated, firewallv1beta1.MatchOperationEq),
			Entry("CtStateUntracked with eq operation", firewallv1beta1.CtStateUntracked, firewallv1beta1.MatchOperationEq),
			Entry("CtStateInvalid with eq operation", firewallv1beta1.CtStateInvalid, firewallv1beta1.MatchOperationEq),
			Entry("CtStateNew with neq operation", firewallv1beta1.CtStateNew, firewallv1beta1.MatchOperationNeq),
			Entry("CtStateEstablished with neq operation", firewallv1beta1.CtStateEstablished, firewallv1beta1.MatchOperationNeq),
		)

		DescribeTable("should correctly handle multiple ctstate values",
			func(ctStateValues []firewallv1beta1.CtStateValue, operation firewallv1beta1.MatchOperation) {
				ruleName := "test-rule-multi"
				actionValue := "1"

				filterRule := &firewallv1beta1.FilterRule{
					Name: &ruleName,
					Match: []firewallv1beta1.Match{
						{
							Op: operation,
							CtState: &firewallv1beta1.MatchCtState{
								Value: ctStateValues,
							},
						},
					},
					Action: firewallv1beta1.ActionCtMark,
					Value:  &actionValue,
				}

				wrapper := &utils.FilterRuleWrapper{FilterRule: filterRule}
				err := wrapper.Add(conn, chain)

				Expect(err).NotTo(HaveOccurred())
			},
			Entry("Multiple states: new and established with eq",
				[]firewallv1beta1.CtStateValue{
					firewallv1beta1.CtStateNew,
					firewallv1beta1.CtStateEstablished,
				},
				firewallv1beta1.MatchOperationEq,
			),
			Entry("Multiple states: established and related with eq",
				[]firewallv1beta1.CtStateValue{
					firewallv1beta1.CtStateEstablished,
					firewallv1beta1.CtStateRelated,
				},
				firewallv1beta1.MatchOperationEq,
			),
			Entry("Multiple states: new, established and related with eq",
				[]firewallv1beta1.CtStateValue{
					firewallv1beta1.CtStateNew,
					firewallv1beta1.CtStateEstablished,
					firewallv1beta1.CtStateRelated,
				},
				firewallv1beta1.MatchOperationEq,
			),
			Entry("Multiple states: new and established with neq",
				[]firewallv1beta1.CtStateValue{
					firewallv1beta1.CtStateNew,
					firewallv1beta1.CtStateEstablished,
				},
				firewallv1beta1.MatchOperationNeq,
			),
			Entry("All states with eq",
				[]firewallv1beta1.CtStateValue{
					firewallv1beta1.CtStateNew,
					firewallv1beta1.CtStateEstablished,
					firewallv1beta1.CtStateRelated,
					firewallv1beta1.CtStateUntracked,
					firewallv1beta1.CtStateInvalid,
				},
				firewallv1beta1.MatchOperationEq,
			),
		)

		It("should correctly apply ctstate match with eq operation", func() {
			ruleName := "test-ctstate-eq"
			actionValue := "1"

			filterRule := &firewallv1beta1.FilterRule{
				Name: &ruleName,
				Match: []firewallv1beta1.Match{
					{
						Op: firewallv1beta1.MatchOperationEq,
						CtState: &firewallv1beta1.MatchCtState{
							Value: []firewallv1beta1.CtStateValue{
								firewallv1beta1.CtStateEstablished,
							},
						},
					},
				},
				Action: firewallv1beta1.ActionCtMark,
				Value:  &actionValue,
			}

			wrapper := &utils.FilterRuleWrapper{FilterRule: filterRule}
			err := wrapper.Add(conn, chain)

			Expect(err).NotTo(HaveOccurred())
		})

		It("should correctly apply ctstate match with neq operation", func() {
			ruleName := "test-ctstate-neq"
			actionValue := "1"

			filterRule := &firewallv1beta1.FilterRule{
				Name: &ruleName,
				Match: []firewallv1beta1.Match{
					{
						Op: firewallv1beta1.MatchOperationNeq,
						CtState: &firewallv1beta1.MatchCtState{
							Value: []firewallv1beta1.CtStateValue{
								firewallv1beta1.CtStateInvalid,
							},
						},
					},
				},
				Action: firewallv1beta1.ActionCtMark,
				Value:  &actionValue,
			}

			wrapper := &utils.FilterRuleWrapper{FilterRule: filterRule}
			err := wrapper.Add(conn, chain)

			Expect(err).NotTo(HaveOccurred())
		})

		It("should correctly combine ctstate with other match types", func() {
			ruleName := "test-ctstate-combined"
			actionValue := "1"
			ipValue := "192.168.1.1"

			filterRule := &firewallv1beta1.FilterRule{
				Name: &ruleName,
				Match: []firewallv1beta1.Match{
					{
						Op: firewallv1beta1.MatchOperationEq,
						Proto: &firewallv1beta1.MatchProto{
							Value: firewallv1beta1.L4ProtoTCP,
						},
					},
					{
						Op: firewallv1beta1.MatchOperationEq,
						IP: &firewallv1beta1.MatchIP{
							Value:    ipValue,
							Position: firewallv1beta1.MatchPositionSrc,
						},
					},
					{
						Op: firewallv1beta1.MatchOperationEq,
						CtState: &firewallv1beta1.MatchCtState{
							Value: []firewallv1beta1.CtStateValue{
								firewallv1beta1.CtStateEstablished,
								firewallv1beta1.CtStateRelated,
							},
						},
					},
				},
				Action: firewallv1beta1.ActionCtMark,
				Value:  &actionValue,
			}

			wrapper := &utils.FilterRuleWrapper{FilterRule: filterRule}
			err := wrapper.Add(conn, chain)

			Expect(err).NotTo(HaveOccurred())
		})

		It("should correctly apply ctstate with metamarkfromctmark action", func() {
			ruleName := "test-ctstate-metamark"

			filterRule := &firewallv1beta1.FilterRule{
				Name: &ruleName,
				Match: []firewallv1beta1.Match{
					{
						Op: firewallv1beta1.MatchOperationEq,
						CtState: &firewallv1beta1.MatchCtState{
							Value: []firewallv1beta1.CtStateValue{
								firewallv1beta1.CtStateNew,
							},
						},
					},
				},
				Action: firewallv1beta1.ActionSetMetaMarkFromCtMark,
			}

			wrapper := &utils.FilterRuleWrapper{FilterRule: filterRule}
			err := wrapper.Add(conn, chain)

			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("When verifying ctstate bit conversion", func() {
		It("should correctly handle rule creation with established state", func() {
			ruleName := "test-expr-check"
			actionValue := "1"

			filterRule := &firewallv1beta1.FilterRule{
				Name: &ruleName,
				Match: []firewallv1beta1.Match{
					{
						Op: firewallv1beta1.MatchOperationEq,
						CtState: &firewallv1beta1.MatchCtState{
							Value: []firewallv1beta1.CtStateValue{
								firewallv1beta1.CtStateEstablished,
							},
						},
					},
				},
				Action: firewallv1beta1.ActionCtMark,
				Value:  &actionValue,
			}

			wrapper := &utils.FilterRuleWrapper{FilterRule: filterRule}
			err := wrapper.Add(conn, chain)
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
