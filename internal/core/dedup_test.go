package core

import (
	"reflect"
	"testing"
)

func TestDedupSignals(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil", nil, nil},
		{"empty", []string{}, nil},
		{"single", []string{"a"}, []string{"a"}},
		{"unique_preserves_order", []string{"c", "a", "b"}, []string{"c", "a", "b"}},
		{"deduplicates", []string{"a", "b", "a", "c", "b"}, []string{"a", "b", "c"}},
		{"all_duplicates", []string{"a", "a", "a"}, []string{"a"}},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := DedupSignals(c.in)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("DedupSignals(%v) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestDedupSignalsSorted(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil", nil, nil},
		{"empty", []string{}, nil},
		{"single", []string{"a"}, []string{"a"}},
		{"sorts", []string{"c", "a", "b"}, []string{"a", "b", "c"}},
		{"deduplicates_then_sorts", []string{"b", "a", "b", "c", "a"}, []string{"a", "b", "c"}},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := DedupSignalsSorted(c.in)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("DedupSignalsSorted(%v) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}
