package happn

import (
	"strings"
	"testing"
)

// TestSubject is a simple struct to test spying on its methods.
type TestSubject struct {
	spy *Spy
}

func (ts *TestSubject) DoSomething(arg1 string, arg2 int) {
	ts.spy.WatchCall(arg1, arg2)
}

func (ts *TestSubject) DoSomethingElse() {
	ts.spy.WatchCall()
}

func (ts *TestSubject) AnotherMethod() {
	ts.spy.WatchCall()
}

func TestSpy_Happened(t *testing.T) {
	spy := NewSpy()
	subject := &TestSubject{spy: spy}

	t.Run("succeeds when all expectations match", func(t *testing.T) {
		spy.Clear()
		subject.DoSomething("hello", 123)
		subject.DoSomethingElse()

		ok, err := spy.Happened(
			Called(subject.DoSomething).WithParams("hello", 123).Once(),
			Called(subject.DoSomethingElse).WithParams(),
		)

		if !ok {
			t.Errorf("Expected Happened to succeed, but it failed: %v", err)
		}
		if err != nil {
			t.Errorf("Expected error to be nil, but got: %v", err)
		}
	})

	t.Run("fails on unexpected call", func(t *testing.T) {
		spy.Clear()
		subject.DoSomething("hello", 123)
		subject.DoSomethingElse() // This one is unexpected

		ok, err := spy.Happened(
			Called(subject.DoSomething).WithParams("hello", 123),
		)

		if ok {
			t.Error("Expected Happened to fail, but it succeeded")
		}
		if err == nil {
			t.Error("Expected an error, but got nil")
		} else if !strings.Contains(err.Error(), "found 1 unexpected call(s)") {
			t.Errorf("Expected error to mention 'unexpected call', but got: %v", err)
		}
	})

	t.Run("fails on missing call", func(t *testing.T) {
		spy.Clear()
		subject.DoSomething("hello", 123)

		ok, err := spy.Happened(
			Called(subject.DoSomething).WithParams("hello", 123),
			Called(subject.DoSomethingElse), // This one is missing
		)

		if ok {
			t.Error("Expected Happened to fail, but it succeeded")
		}
		if err == nil {
			t.Error("Expected an error, but got nil")
		} else if !strings.Contains(err.Error(), "but it was not called") {
			t.Errorf("Expected error to mention 'not called', but got: %v", err)
		}
	})

	t.Run("fails on mismatched parameters", func(t *testing.T) {
		spy.Clear()
		subject.DoSomething("world", 456)

		ok, err := spy.Happened(
			Called(subject.DoSomething).WithParams("hello", 123),
		)

		if ok {
			t.Error("Expected Happened to fail, but it succeeded")
		}
		if err == nil {
			t.Error("Expected an error, but got nil")
		} else if !strings.Contains(err.Error(), "but it was called 0 times with those arguments") {
			t.Errorf("Expected error to mention '0 times with those arguments', but got: %v", err)
		}
	})

	t.Run("fails on wrong number of calls", func(t *testing.T) {
		spy.Clear()
		subject.DoSomething("hello", 123)
		subject.DoSomething("hello", 123)

		ok, err := spy.Happened(
			Called(subject.DoSomething).WithParams("hello", 123).Once(),
		)

		if ok {
			t.Error("Expected Happened to fail, but it succeeded")
		}
		if err == nil {
			t.Error("Expected an error, but got nil")
		} else if !strings.Contains(err.Error(), "expected 'DoSomething' to be called 1 time(s), but it was called 2 time(s)") {
			t.Errorf("Expected error to mention call count mismatch, but got: %v", err)
		}
	})

	t.Run("succeeds with Times(n)", func(t *testing.T) {
		spy.Clear()
		subject.DoSomething("repeat", 0)
		subject.DoSomething("repeat", 0)
		subject.DoSomething("repeat", 0)

		ok, err := spy.Happened(
			Called(subject.DoSomething).WithParams("repeat", 0).Times(3),
		)

		if !ok {
			t.Errorf("Expected Happened to succeed with Times(3), but it failed: %v", err)
		}
	})

	t.Run("succeeds with Anything matcher", func(t *testing.T) {
		spy.Clear()
		subject.DoSomething("any string", 999)

		ok, err := spy.Happened(
			Called(subject.DoSomething).WithParams(Anything, 999),
		)

		if !ok {
			t.Errorf("Expected Happened to succeed with Anything matcher, but it failed: %v", err)
		}
	})
}

func TestSpy_ClearAndTotalCalls(t *testing.T) {
	spy := NewSpy()
	subject := &TestSubject{spy: spy}

	if spy.TotalCalls() != 0 {
		t.Errorf("Expected 0 total calls for a new spy, but got %d", spy.TotalCalls())
	}

	subject.DoSomething("a", 1)
	subject.DoSomethingElse()

	if spy.TotalCalls() != 2 {
		t.Errorf("Expected 2 total calls, but got %d", spy.TotalCalls())
	}

	spy.Clear()

	if spy.TotalCalls() != 0 {
		t.Errorf("Expected 0 total calls after Clear(), but got %d", spy.TotalCalls())
	}
}
