package queue

import (
	"testing"

	"tiai/agent/internal/models"
)

func TestEnqueuePeekRemoveFIFO(t *testing.T) {
	q, err := New(t.TempDir(), 10)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if q.Depth() != 0 {
		t.Fatalf("expected empty queue, got depth %d", q.Depth())
	}

	for _, id := range []string{"a", "b", "c"} {
		if err := q.Enqueue(Item{CommandID: id, Result: models.CommandResult{Status: "succeeded"}}); err != nil {
			t.Fatalf("Enqueue %s: %v", id, err)
		}
	}
	if q.Depth() != 3 {
		t.Fatalf("expected depth 3, got %d", q.Depth())
	}

	// FIFO: oldest ("a") comes out first.
	item, path, err := q.Peek()
	if err != nil || item == nil {
		t.Fatalf("Peek: item=%v err=%v", item, err)
	}
	if item.CommandID != "a" {
		t.Fatalf("expected oldest 'a', got %q", item.CommandID)
	}
	if err := q.Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if q.Depth() != 2 {
		t.Fatalf("expected depth 2 after remove, got %d", q.Depth())
	}
}

func TestEnqueueDropsOldestWhenFull(t *testing.T) {
	q, err := New(t.TempDir(), 2)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, id := range []string{"a", "b", "c"} {
		if err := q.Enqueue(Item{CommandID: id}); err != nil {
			t.Fatalf("Enqueue %s: %v", id, err)
		}
	}
	if q.Depth() != 2 {
		t.Fatalf("expected cap at 2, got %d", q.Depth())
	}
	// "a" should have been dropped; oldest remaining is "b".
	item, _, err := q.Peek()
	if err != nil || item == nil {
		t.Fatalf("Peek: item=%v err=%v", item, err)
	}
	if item.CommandID != "b" {
		t.Fatalf("expected 'b' after dropping oldest, got %q", item.CommandID)
	}
}

func TestPeekEmpty(t *testing.T) {
	q, _ := New(t.TempDir(), 10)
	item, path, err := q.Peek()
	if err != nil {
		t.Fatalf("Peek empty: %v", err)
	}
	if item != nil || path != "" {
		t.Fatalf("expected nil item/empty path, got %v %q", item, path)
	}
}
