package main

import (
	"reflect"
	"testing"
)

func TestParseDomains(t *testing.T) {
	tests := []struct {
		input    uint16
		expected []int
	}{
		{input: uint16(0), expected: nil},
		{input: uint16(1), expected: []int{1}},
		{input: uint16(1 << 3), expected: []int{4}},
		{input: uint16(1 + 1<<4), expected: []int{1, 5}},
		{input: uint16(1<<2 + 1<<11 + 1<<7), expected: []int{3, 8, 12}},
	}

	for _, test := range tests {
		actual := parseDomains(test.input)
		if !reflect.DeepEqual(actual, test.expected) {
			t.Errorf("Unexpected result %v, wanted %v", actual, test.expected)
		}
	}
}

func TestParseCapabilities(t *testing.T) {
	tests := []struct {
		input    uint64
		expected []string
	}{
		{input: uint64(0), expected: nil},
		{input: uint64(1), expected: []string{"get_opaque"}},
		{input: uint64(1 + 1<<7), expected: []string{"get_opaque", "sign_ecdsa"}},
		{input: uint64(1<<7 + 1<<3 + 1), expected: []string{"get_opaque", "put_asymmetric_key", "sign_ecdsa"}},
	}

	for _, test := range tests {
		actual := parseCapabilities(test.input)
		if !reflect.DeepEqual(actual, test.expected) {
			t.Errorf("Unexpected result %v, wanted %v", actual, test.expected)
		}
	}
}
