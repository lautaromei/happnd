package happn

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"sync"
)

const Anything = "*"

type Spy struct {
	calls map[string][][]any
	sync.RWMutex
}

func NewSpy() *Spy {
	return &Spy{
		calls: make(map[string][][]any),
	}
}

func (m *Spy) RememberCall(params ...any) {
	pc, _, _, ok := runtime.Caller(1)
	if !ok {
		panic("Couldn't get the caller information")
	}
	functionPath := cleanFuncName(runtime.FuncForPC(pc).Name())

	m.Lock()
	defer m.Unlock()
	m.calls[functionPath] = append(m.calls[functionPath], params)
}

func (m *Spy) Clear() {
	m.Lock()
	defer m.Unlock()
	m.calls = make(map[string][][]any)
}

func (m *Spy) TotalCalls() int {
	m.RLock()
	defer m.RUnlock()
	count := 0
	for _, callsForFunc := range m.calls {
		count += len(callsForFunc)
	}
	return count
}

func (m *Spy) Happened(that ...*CallAssertion) (bool, error) {
	m.RLock()
	defer m.RUnlock()

	// Create a mutable copy of the calls to work with.
	copiedCalls := make(map[string][][]any, len(m.calls))
	for funcName, calls := range m.calls {
		callsCopy := make([][]any, len(calls))
		copy(callsCopy, calls)
		copiedCalls[funcName] = callsCopy
	}

	errs := m.verifyExpectations(copiedCalls, that)

	if unexpectedErr := m.checkUnexpectedCalls(copiedCalls); unexpectedErr != nil {
		errs = append(errs, unexpectedErr.Error())
	}

	if len(errs) > 0 {
		return false, fmt.Errorf("found %d error(s) during expectation assertion:\n- %s", len(errs), strings.Join(errs, "\n- "))
	}

	return true, nil
}

// verifyExpectations checks each assertion against the recorded calls, consuming them if they match.
func (m *Spy) verifyExpectations(calls map[string][][]any, assertions []*CallAssertion) []string {
	var errs []string
	for _, assertion := range assertions {
		if assertion.err != nil {
			errs = append(errs, assertion.err.Error())
			continue
		}

		matchingCalls := m.filterMatchingCalls(calls, assertion)
		actualCount := len(matchingCalls)

		if actualCount != assertion.times {
			allCallsForFunc := calls[assertion.funcName]
			errs = append(errs, m.buildMismatchedCallError(assertion, actualCount, allCallsForFunc))
		} else if actualCount > 0 {
			// Consume the verified calls from the copy
			for i := 0; i < assertion.times; i++ {
				m.consumeCall(calls, assertion)
			}
		}
	}
	return errs
}

// checkUnexpectedCalls checks for any calls that were not consumed during verification.
func (m *Spy) checkUnexpectedCalls(calls map[string][][]any) error {
	unexpectedCount := 0
	var unexpectedDetails []string
	for funcName, remainingCalls := range calls {
		if len(remainingCalls) > 0 {
			unexpectedCount += len(remainingCalls)
			unexpectedDetails = append(unexpectedDetails, fmt.Sprintf("  - %s was called %d time(s) unexpectedly with arguments: %v", funcName, len(remainingCalls), remainingCalls))
		}
	}
	if unexpectedCount > 0 {
		return fmt.Errorf("found %d unexpected call(s):\n%s", unexpectedCount, strings.Join(unexpectedDetails, "\n"))
	}
	return nil
}

// buildMismatchedCallError creates a detailed error message for a failed assertion.
func (m *Spy) buildMismatchedCallError(a *CallAssertion, actualCount int, allCallsForFunc [][]any) string {
	if actualCount == 0 {
		if len(allCallsForFunc) > 0 {
			expectedArgsStr := "with any arguments"
			if len(a.expectedArgs) > 0 {
				expectedArgsStr = fmt.Sprintf("with arguments %v", a.expectedArgs)
			}
			var receivedCallsStr strings.Builder
			for i, call := range allCallsForFunc {
				fmt.Fprintf(&receivedCallsStr, "\n    - Call %d: %v", i+1, call)
			}
			return fmt.Sprintf("expected '%s' to be called %d time(s) %s, but it was called 0 times with those arguments. %d call(s) were recorded with the following arguments:%s",
				a.funcName, a.times, expectedArgsStr, len(allCallsForFunc), receivedCallsStr.String())
		}
		return fmt.Sprintf("expected '%s' to be called %d time(s), but it was not called.", a.funcName, a.times)
	}
	return fmt.Sprintf("expected '%s' to be called %d time(s), but it was called %d time(s)", a.funcName, a.times, actualCount)
}

func (m *Spy) filterMatchingCalls(calls map[string][][]any, a *CallAssertion) [][]any {
	recordedCalls, found := calls[a.funcName]
	if !found {
		return nil
	}

	if len(a.expectedArgs) == 0 {
		return recordedCalls
	}

	matchingCalls := make([][]any, 0)
	for _, call := range recordedCalls {
		if paramsMatch(a.expectedArgs, call) {
			matchingCalls = append(matchingCalls, call)
		}
	}
	return matchingCalls
}

func (m *Spy) consumeCall(calls map[string][][]any, a *CallAssertion) {
	allCalls := calls[a.funcName]
	for i, call := range allCalls {
		if paramsMatch(a.expectedArgs, call) {
			// Remove the element at index i
			calls[a.funcName] = append(allCalls[:i], allCalls[i+1:]...)
			return
		}
	}
}

func paramsMatch(expected, actual []any) bool {
	if len(expected) != len(actual) {
		return false
	}

	for i, exp := range expected {
		act := actual[i]
		if exp == Anything {
			continue
		}
		if matcher, ok := exp.(Matcher); ok {
			if !matcher.Matches(act) {
				return false
			}
		} else if !reflect.DeepEqual(exp, act) {
			return false
		}
	}
	return true
}

func cleanFuncName(fullName string) string {
	fullName = strings.TrimSuffix(fullName, "-fm")
	parts := strings.Split(fullName, ".")
	return parts[len(parts)-1]
}

// --- Matchers ---

type Matcher interface {
	Matches(x any) bool
	String() string
}
