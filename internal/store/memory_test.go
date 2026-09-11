package store

import "testing"

func TestMemoryConformance(t *testing.T) {
	runConformance(t, func(t *testing.T) testStore {
		t.Helper()
		return NewMemory()
	})
}
