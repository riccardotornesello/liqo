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

package utils

import (
	"net"
	"testing"

	"github.com/google/nftables"

	firewallv1beta1 "github.com/liqotech/liqo/apis/networking/v1beta1/firewall"
)

func TestHasIPSetMatch(t *testing.T) {
	tests := []struct {
		name     string
		matches  []firewallv1beta1.Match
		expected bool
	}{
		{
			name:     "empty matches",
			matches:  []firewallv1beta1.Match{},
			expected: false,
		},
		{
			name: "single IP match",
			matches: []firewallv1beta1.Match{
				{
					Op: firewallv1beta1.MatchOperationEq,
					IP: &firewallv1beta1.MatchIP{
						Value:    "192.168.1.1",
						Position: firewallv1beta1.MatchPositionSrc,
					},
				},
			},
			expected: false,
		},
		{
			name: "subnet match",
			matches: []firewallv1beta1.Match{
				{
					Op: firewallv1beta1.MatchOperationEq,
					IP: &firewallv1beta1.MatchIP{
						Value:    "192.168.1.0/24",
						Position: firewallv1beta1.MatchPositionSrc,
					},
				},
			},
			expected: false,
		},
		{
			name: "IP set match",
			matches: []firewallv1beta1.Match{
				{
					Op: firewallv1beta1.MatchOperationEq,
					IP: &firewallv1beta1.MatchIP{
						Value:    "192.168.1.1,192.168.1.2,192.168.1.3",
						Position: firewallv1beta1.MatchPositionSrc,
					},
				},
			},
			expected: true,
		},
		{
			name: "mixed matches with IP set",
			matches: []firewallv1beta1.Match{
				{
					Op: firewallv1beta1.MatchOperationEq,
					IP: &firewallv1beta1.MatchIP{
						Value:    "192.168.1.0/24",
						Position: firewallv1beta1.MatchPositionSrc,
					},
				},
				{
					Op: firewallv1beta1.MatchOperationEq,
					IP: &firewallv1beta1.MatchIP{
						Value:    "10.0.0.1,10.0.0.2",
						Position: firewallv1beta1.MatchPositionDst,
					},
				},
			},
			expected: true,
		},
		{
			name: "IP range match",
			matches: []firewallv1beta1.Match{
				{
					Op: firewallv1beta1.MatchOperationEq,
					IP: &firewallv1beta1.MatchIP{
						Value:    "192.168.1.1-192.168.1.10",
						Position: firewallv1beta1.MatchPositionSrc,
					},
				},
			},
			expected: false,
		},
		{
			name: "non-IP match",
			matches: []firewallv1beta1.Match{
				{
					Op: firewallv1beta1.MatchOperationEq,
					Proto: &firewallv1beta1.MatchProto{
						Value: firewallv1beta1.L4ProtoTCP,
					},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasIPSetMatch(tt.matches)
			if result != tt.expected {
				t.Errorf("HasIPSetMatch() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestGetExpectedIPSets(t *testing.T) {
	tests := []struct {
		name             string
		matches          []firewallv1beta1.Match
		expectedIPSets   int
		firstSetIPCount  int
		secondSetIPCount int
	}{
		{
			name:           "empty matches",
			matches:        []firewallv1beta1.Match{},
			expectedIPSets: 0,
		},
		{
			name: "single IP set",
			matches: []firewallv1beta1.Match{
				{
					Op: firewallv1beta1.MatchOperationEq,
					IP: &firewallv1beta1.MatchIP{
						Value:    "192.168.1.1,192.168.1.2,192.168.1.3",
						Position: firewallv1beta1.MatchPositionSrc,
					},
				},
			},
			expectedIPSets:  1,
			firstSetIPCount: 3,
		},
		{
			name: "two IP sets",
			matches: []firewallv1beta1.Match{
				{
					Op: firewallv1beta1.MatchOperationEq,
					IP: &firewallv1beta1.MatchIP{
						Value:    "192.168.1.1,192.168.1.2",
						Position: firewallv1beta1.MatchPositionSrc,
					},
				},
				{
					Op: firewallv1beta1.MatchOperationEq,
					IP: &firewallv1beta1.MatchIP{
						Value:    "10.0.0.1,10.0.0.2,10.0.0.3,10.0.0.4",
						Position: firewallv1beta1.MatchPositionDst,
					},
				},
			},
			expectedIPSets:   2,
			firstSetIPCount:  2,
			secondSetIPCount: 4,
		},
		{
			name: "mixed with non-IP set",
			matches: []firewallv1beta1.Match{
				{
					Op: firewallv1beta1.MatchOperationEq,
					IP: &firewallv1beta1.MatchIP{
						Value:    "192.168.1.0/24",
						Position: firewallv1beta1.MatchPositionSrc,
					},
				},
				{
					Op: firewallv1beta1.MatchOperationEq,
					IP: &firewallv1beta1.MatchIP{
						Value:    "10.0.0.1,10.0.0.2",
						Position: firewallv1beta1.MatchPositionDst,
					},
				},
			},
			expectedIPSets:  1,
			firstSetIPCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getExpectedIPSets(tt.matches)
			if len(result) != tt.expectedIPSets {
				t.Errorf("getExpectedIPSets() returned %d sets, expected %d", len(result), tt.expectedIPSets)
			}
			if tt.expectedIPSets > 0 && len(result[0]) != tt.firstSetIPCount {
				t.Errorf("getExpectedIPSets() first set has %d IPs, expected %d", len(result[0]), tt.firstSetIPCount)
			}
			if tt.expectedIPSets > 1 && len(result[1]) != tt.secondSetIPCount {
				t.Errorf("getExpectedIPSets() second set has %d IPs, expected %d", len(result[1]), tt.secondSetIPCount)
			}
		})
	}
}

func TestCompareIPSetElements(t *testing.T) {
	tests := []struct {
		name        string
		expectedIPs []net.IP
		actualIPs   []net.IP
		expected    bool
	}{
		{
			name:        "empty sets",
			expectedIPs: []net.IP{},
			actualIPs:   []net.IP{},
			expected:    true,
		},
		{
			name:        "matching single IP",
			expectedIPs: []net.IP{net.ParseIP("192.168.1.1")},
			actualIPs:   []net.IP{net.ParseIP("192.168.1.1")},
			expected:    true,
		},
		{
			name:        "matching multiple IPs same order",
			expectedIPs: []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.2")},
			actualIPs:   []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.2")},
			expected:    true,
		},
		{
			name:        "matching multiple IPs different order",
			expectedIPs: []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.2")},
			actualIPs:   []net.IP{net.ParseIP("192.168.1.2"), net.ParseIP("192.168.1.1")},
			expected:    true,
		},
		{
			name:        "different count",
			expectedIPs: []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.2")},
			actualIPs:   []net.IP{net.ParseIP("192.168.1.1")},
			expected:    false,
		},
		{
			name:        "different IPs",
			expectedIPs: []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.2")},
			actualIPs:   []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.3")},
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert actualIPs to SetElements
			elements := make([]nftables.SetElement, len(tt.actualIPs))
			for i, ip := range tt.actualIPs {
				elements[i] = nftables.SetElement{Key: ip.To4()}
			}

			result := compareIPSetElements(elements, tt.expectedIPs)
			if result != tt.expected {
				t.Errorf("compareIPSetElements() = %v, expected %v", result, tt.expected)
			}
		})
	}
}
