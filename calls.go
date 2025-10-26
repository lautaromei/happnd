package main

import (
	"fmt"
	"path"
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
	_, methodName := splitFullFuncName(fullName)
	return &CalledFunc{
		times:           1,
		funcName:        methodName,
		callerComponent: "", // No specific caller expected by default
	}
}

func Struct(s any) *StructAssertion {
	t := reflect.TypeOf(s)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return &StructAssertion{
			err: fmt.Errorf("Struct() expects a struct, but received a value of type %T", s),
		}
	}

	// The component name is like "main.DogWalker"
	// PkgPath() can be long, so we just take the last part.
	pkgName := path.Base(t.PkgPath())
	componentName := fmt.Sprintf("%s.%s", pkgName, t.Name())

	return &StructAssertion{callerComponent: componentName}
}

type StructAssertion struct {
	callerComponent string
	err             error
}

type CalledFunc struct {
	expectedArgs []any

	callerComponent string
	funcName        string
	err             error
	times           int
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

func (sa *StructAssertion) Called(function any) *CalledFunc {
	if sa.err != nil {
		return &CalledFunc{err: sa.err}
	}

	cf := Called(function)
	if cf.err != nil {
		return cf
	}

	cf.callerComponent = sa.callerComponent
	return cf
}
