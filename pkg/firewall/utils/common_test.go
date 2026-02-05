// Copyright 2019-2026 The Liqo Authors
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

package utils

import (
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	firewallv1beta1 "github.com/liqotech/liqo/apis/networking/v1beta1/firewall"
)

var _ = Describe("Firewall common utilities", func() {
	Describe("GetIPValueType", func() {
		It("returns Void for nil value", func() {
			var v *string = nil
			typ, err := GetIPValueType(v)
			Expect(err).To(BeNil())
			Expect(typ).To(Equal(firewallv1beta1.IPValueTypeVoid))
		})

		It("detects CIDR as Subnet", func() {
			s := "10.0.0.0/24"
			typ, err := GetIPValueType(&s)
			Expect(err).To(BeNil())
			Expect(typ).To(Equal(firewallv1beta1.IPValueTypeSubnet))
		})

		It("detects single IP", func() {
			s := "192.168.1.1"
			typ, err := GetIPValueType(&s)
			Expect(err).To(BeNil())
			Expect(typ).To(Equal(firewallv1beta1.IPValueTypeIP))
		})

		It("detects IP range", func() {
			s := "192.168.1.1-192.168.1.10"
			typ, err := GetIPValueType(&s)
			Expect(err).To(BeNil())
			Expect(typ).To(Equal(firewallv1beta1.IPValueTypeRange))
		})

		It("detects named set", func() {
			s := "@myset"
			typ, err := GetIPValueType(&s)
			Expect(err).To(BeNil())
			Expect(typ).To(Equal(firewallv1beta1.IPValueTypeNamedSet))
		})

		It("returns error for invalid value", func() {
			s := "not-an-ip"
			typ, err := GetIPValueType(&s)
			Expect(err).ToNot(BeNil())
			Expect(typ).To(Equal(firewallv1beta1.IPValueTypeVoid))
		})
	})

	Describe("GetIPValueRange", func() {
		It("parses a valid range", func() {
			start, end, err := GetIPValueRange("192.168.1.1 - 192.168.1.10")
			Expect(err).To(BeNil())
			Expect(start.String()).To(Equal(net.ParseIP("192.168.1.1").String()))
			Expect(end.String()).To(Equal(net.ParseIP("192.168.1.10").String()))
		})

		It("returns error on invalid format", func() {
			_, _, err := GetIPValueRange("192.168.1.1")
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("GetIPValueNamedSet", func() {
		It("parses valid named set", func() {
			name, err := GetIPValueNamedSet("@somename")
			Expect(err).To(BeNil())
			Expect(name).To(Equal("somename"))
		})

		It("returns error for missing @", func() {
			_, err := GetIPValueNamedSet("somename")
			Expect(err).ToNot(BeNil())
		})

		It("returns error for empty name", func() {
			_, err := GetIPValueNamedSet("@")
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("GetPortValueType", func() {
		It("returns Void for nil pointer", func() {
			var p *string = nil
			typ, err := GetPortValueType(p)
			Expect(err).To(BeNil())
			Expect(typ).To(Equal(firewallv1beta1.PortValueTypeVoid))
		})

		It("detects port range", func() {
			s := "1000-2000"
			typ, err := GetPortValueType(&s)
			Expect(err).To(BeNil())
			Expect(typ).To(Equal(firewallv1beta1.PortValueTypeRange))
		})

		It("detects single port", func() {
			s := "8080"
			typ, err := GetPortValueType(&s)
			Expect(err).To(BeNil())
			Expect(typ).To(Equal(firewallv1beta1.PortValueTypePort))
		})

		It("returns error for invalid port value", func() {
			s := "notaport"
			typ, err := GetPortValueType(&s)
			Expect(err).ToNot(BeNil())
			Expect(typ).To(Equal(firewallv1beta1.PortValueTypeVoid))
		})
	})
})
