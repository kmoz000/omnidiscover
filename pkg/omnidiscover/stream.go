package omnidiscover

import (
	"context"
	"sync"
	"sync/atomic"
)

type ownedStreamQueue struct {
	mu      sync.Mutex
	max     int
	pending map[LinkKey]*Event
	order   []LinkKey
	head    int
	notify  chan struct{}
	done    chan struct{}
	closed  bool
	dropped *atomic.Uint64
}

func newOwnedStreamQueue(max int, dropped *atomic.Uint64) *ownedStreamQueue {
	return &ownedStreamQueue{max: max, pending: make(map[LinkKey]*Event, max), order: make([]LinkKey, 0, max), notify: make(chan struct{}, 1), done: make(chan struct{}), dropped: dropped}
}

func (q *ownedStreamQueue) enqueue(view EventView) {
	if view.Link == nil {
		return
	}
	key := view.Link.Key
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return
	}
	if existing, ok := q.pending[key]; ok {
		oldKind, oldChanged := existing.Kind, existing.Changed
		cloneEventInto(existing, view)
		if oldKind == EventAdded && view.Kind == EventChanged {
			existing.Kind = EventAdded
		}
		existing.Changed |= oldChanged
		q.mu.Unlock()
		return
	}
	if len(q.pending) >= q.max {
		q.dropped.Add(1)
		q.mu.Unlock()
		return
	}
	e := &Event{}
	cloneEventInto(e, view)
	q.pending[key] = e
	q.order = append(q.order, key)
	q.mu.Unlock()
	select {
	case q.notify <- struct{}{}:
	default:
	}
}

func (q *ownedStreamQueue) pop() (*Event, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for q.head < len(q.order) {
		key := q.order[q.head]
		q.head++
		if event, ok := q.pending[key]; ok {
			delete(q.pending, key)
			q.compact()
			return event, true
		}
	}
	q.compact()
	return nil, false
}

func (q *ownedStreamQueue) compact() {
	if q.head > 1024 && q.head*2 >= len(q.order) {
		copy(q.order, q.order[q.head:])
		q.order = q.order[:len(q.order)-q.head]
		q.head = 0
	}
}

func (q *ownedStreamQueue) pump(ctx context.Context, out chan<- Event) {
	for {
		if event, ok := q.pop(); ok {
			select {
			case out <- *event:
				continue
			case <-ctx.Done():
				return
			case <-q.done:
				return
			}
		}
		select {
		case <-q.notify:
		case <-ctx.Done():
			return
		case <-q.done:
			// Drain if the context is still alive; otherwise the ctx case wins.
			for {
				event, ok := q.pop()
				if !ok {
					return
				}
				select {
				case out <- *event:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func (q *ownedStreamQueue) close() {
	q.mu.Lock()
	if !q.closed {
		q.closed = true
		close(q.done)
	}
	q.mu.Unlock()
}
