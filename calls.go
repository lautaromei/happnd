package main

import (
	"fmt"
	"reflect"
	"runtime"
)

func Called(function any) *CalledFunc {
	v := reflect.ValueOf(function)
	if v.Kind() != reflect.Func {
		return &CalledFunc{
			err: fmt.Errorf("Called() expects a function, but received a value of type %T", function),
		}
	}

	fullName := runtime.FuncForPC(v.Pointer()).Name()
	return &CalledFunc{
		times:    1,
		funcName: cleanFuncName(fullName),
	}
}

type CalledFunc struct {
	expectedArgs []any

	funcName string
	err      error
	times    int
}

func (a *CalledFunc) Times(n int) *CalledFunc {
	if a.err != nil {
		return a
	}
	a.times = n
	return a
}

func (a *CalledFunc) Once() *CalledFunc {
	return a.Times(1)
}

func (a *CalledFunc) WithParams(params ...any) *CalledFunc {
	if a.err != nil {
		return a
	}
	a.expectedArgs = params
	return a
}
