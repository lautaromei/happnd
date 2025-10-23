# happn - A Simple Spy for Go

`happn` is a lightweight spy library for Go, designed to make testing interactions between components simple and clear. It allows you to record function calls and then verify that those calls happened as expected, including arguments and call counts.

## Purpose

In testing, it's crucial to verify that components interact correctly with their dependencies. However, traditional mocking libraries can sometimes be heavyweight, bundling assertion logic with stubbing behavior.

`happn` provides a focused solution by separating the **spy** from your test doubles (stubs, fakes, etc.). This is useful to:

*   **Decouple Spying Logic:** Keep your test stubs clean and focused on providing canned answers. `happn` handles the observation and assertion of calls, promoting a clear separation of concerns.
*   **Use Spying On-Demand:** Easily add spying capabilities to a simple stub only when you need to assert interactions. This avoids using a mock when a simple stub is all that's required for a test.

## Basic Usage

```go
package main

import "github.com/lautaromei/happnd"

type Greeter interface {
	Greet(name string) string
}

type MyGreeter struct{}

func (mg *MyGreeter) Greet(name string) string {
	return "Hello, " + name
}

type GreeterSpy struct {
	happn.Spy 
}

func (gs *GreeterSpy) Greet(name string) string {
	gs.WatchCall(name) 
	return "Hello, " + name 
}
```

Test File
```go
// main_test.go
package main

import (
	"testing"
	"github.com/lautaromei/happnd"
)

func TestGreeterInteraction(t *testing.T) {
	spy := happn.NewSpy()

	greeter := &GreeterSpy{spy}

	greeter.Greet("World")
	greeter.Greet("Go")

	ok, err := spy.Happened(
		happn.Called(greeter.Greet).WithParams("World").Once(), 
		happn.Called(greeter.Greet).WithParams("Go").Once(), 
	)

	if !ok {
		t.Fatalf("Not happened: %v", err)
	}
}
```