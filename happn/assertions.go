package happn

import (
	"fmt"
	"reflect"
	"runtime"
)

// Called starts a verification chain for a specific function.
func Called(function any) *CallAssertion {
	v := reflect.ValueOf(function)
	if v.Kind() != reflect.Func {
		return &CallAssertion{
			err: fmt.Errorf("Called() expects a function, but received a value of type %T", function),
		}
	}

	fullName := runtime.FuncForPC(v.Pointer()).Name()
	return &CallAssertion{
		times:    1,
		funcName: cleanFuncName(fullName),
	}
}

// CallAssertion allows building assertions about function calls.
type CallAssertion struct {
	expectedArgs []any

	funcName string
	err      error
	times    int
}

func (a *CallAssertion) Times(n int) *CallAssertion {
	if a.err != nil {
		return a
	}
	a.times = n
	return a
}

func (a *CallAssertion) Once() *CallAssertion {
	return a.Times(1)
}

func (a *CallAssertion) WithParams(params ...any) *CallAssertion {
	if a.err != nil {
		return a
	}
	a.expectedArgs = params
	return a
}
