package main

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"sync"
)

const Anything = "*"

// CallRecord stores detailed information about a single function call.
type CallRecord struct {
	CallerComponent string
	CallerMethod    string
	CalleeComponent string
	CalleeMethod    string
	Params          []any
}

// failureRecord stores information about a failed assertion.
type failureRecord struct {
	failedAssertion *CalledFunc
	reason          string
	actualCount     int // Add actual count for better graph annotations
}

type Spy struct {
	calls    []*CallRecord
	failures []*failureRecord // Stores info about all failed expectations.
	sync.RWMutex
	unexpectedCalls []*CallRecord // Temporarily stores unexpected calls for graph drawing.
}

func NewSpy() *Spy {
	return &Spy{
		calls: make([]*CallRecord, 0),
	}
}

func (m *Spy) WatchCall(params ...any) {
	pcs := make([]uintptr, 3)
	// 0: runtime.Callers, 1: WatchCall, 2: Callee (e.g., DoWork), 3: Caller (e.g., Test function)
	n := runtime.Callers(2, pcs)
	if n < 1 {
		panic("could not get caller information")
	}

	calleeFrame, _ := runtime.CallersFrames(pcs[0:1]).Next()
	calleeComponent, calleeMethod := splitFullFuncName(calleeFrame.Function)

	callerComponent, callerMethod := "Test", "Unknown"
	if n > 1 {
		callerFrame, _ := runtime.CallersFrames(pcs[1:2]).Next()
		callerComponent, callerMethod = splitFullFuncName(callerFrame.Function)
	}

	m.Lock()
	defer m.Unlock()
	m.calls = append(m.calls, &CallRecord{
		CallerComponent: callerComponent,
		CallerMethod:    callerMethod,
		CalleeComponent: calleeComponent,
		CalleeMethod:    calleeMethod,
		Params:          params,
	})
}

func (m *Spy) Clear() {
	m.Lock()
	defer m.Unlock()
	m.failures = nil
	m.calls = make([]*CallRecord, 0)
	m.unexpectedCalls = nil
}

func (m *Spy) TotalCalls() int {
	m.RLock()
	defer m.RUnlock()
	return len(m.calls)
}

func (m *Spy) Happened(that ...*CalledFunc) (bool, error) {
	m.RLock()
	defer m.RUnlock()
	// Clear any previous unexpected call records before a new check.
	m.unexpectedCalls = nil

	// Group recorded calls by function name for efficient lookup.
	callsByFunc := make(map[string][]*CallRecord)
	for _, call := range m.calls {
		callsByFunc[call.CalleeMethod] = append(callsByFunc[call.CalleeMethod], call)
	}

	// Create a mutable copy of the grouped calls to work with.
	copiedCalls := make(map[string][]*CallRecord, len(callsByFunc))
	for funcName, calls := range callsByFunc {
		callsCopy := make([]*CallRecord, len(calls))
		copy(callsCopy, calls)
		copiedCalls[funcName] = callsCopy
	}

	errs := m.verifyExpectations(copiedCalls, that)

	// Check for unexpected calls *after* verifying expectations.
	// The `verifyExpectations` function sets `lastFailure` if an assertion fails.
	if unexpectedErr := m.checkUnexpectedCalls(copiedCalls); unexpectedErr != nil {
		errs = append(errs, unexpectedErr.Error())
	}

	if len(errs) > 0 {
		// On failure, generate the graph and include it in the error.
		// The graph drawing logic will automatically include failure annotations if `m.lastFailure` was set.

		graph := m.DrawGraph()
		errorReport := fmt.Sprintf("\nfound %d error(s) during expectation assertion:\n- %s", len(errs), strings.Join(errs, "\n- "))
		return false, fmt.Errorf("%s%s", graph, errorReport)
	}

	return true, nil
}

// verifyExpectations checks each assertion against the recorded calls, consuming them if they match.
func (m *Spy) verifyExpectations(calls map[string][]*CallRecord, assertions []*CalledFunc) []string {
	var errs []string
	m.failures = make([]*failureRecord, 0) // Reset failures for this run.

	for _, assertion := range assertions {
		if assertion.err != nil {
			errs = append(errs, assertion.err.Error())
			continue
		}

		matchingCalls := m.filterMatchingCalls(calls, assertion)
		actualCount := len(matchingCalls)

		if actualCount != assertion.times {
			// For error reporting, get all calls for this function name from the original map.
			allCallsForFunc := calls[assertion.funcName]
			errMsg := m.buildMismatchedCallError(assertion, actualCount, allCallsForFunc)
			errs = append(errs, errMsg)
			m.failures = append(m.failures, &failureRecord{failedAssertion: assertion, reason: errMsg, actualCount: actualCount})
			// If the function was called but with the wrong parameters,
			// consume those calls to prevent them from being reported as "unexpected".
			if actualCount == 0 && len(allCallsForFunc) > 0 {
				delete(calls, assertion.funcName)
			} else if actualCount > 0 {
				// Consume the calls that did match to prevent them from being reported as unexpected,
				// even though the count was wrong.
				delete(calls, assertion.funcName)
			}
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
func (m *Spy) checkUnexpectedCalls(calls map[string][]*CallRecord) error {
	unexpectedCount := 0
	m.unexpectedCalls = make([]*CallRecord, 0)
	var unexpectedDetails []string
	for _, remainingCalls := range calls {
		if len(remainingCalls) > 0 {
			for _, call := range remainingCalls {
				unexpectedCount++
				nodeName := fmt.Sprintf("%s.%s", call.CalleeComponent, call.CalleeMethod)
				boxLines := m.formatNodeAsLines(nodeName, call.Params, true, 1)
				// Make the box bold
				boldBox := fmt.Sprintf("%s%s%s\n%s%s%s%s\n%s%s%s", bold, red, boxLines[0], bold, red, boxLines[1], reset, bold, red, boxLines[2])
				unexpectedDetails = append(unexpectedDetails, boldBox)
				m.unexpectedCalls = append(m.unexpectedCalls, call)
			}
		}
	}
	if unexpectedCount > 0 {
		return fmt.Errorf("found %d unexpected call(s):\n%s", unexpectedCount, strings.Join(unexpectedDetails, "\n\n"))
	}
	return nil
}

// buildMismatchedCallError creates a detailed error message for a failed assertion.
func (m *Spy) buildMismatchedCallError(a *CalledFunc, actualCount int, allCallsForFunc []*CallRecord) string {
	cleanName := cleanFuncName(a.funcName)
	if actualCount == 0 {
		if len(allCallsForFunc) > 0 {
			// If a specific caller was expected, the error should be about the caller mismatch.
			if a.callerComponent != "" {
				callersFound := make(map[string]bool)
				for _, call := range allCallsForFunc {
					callersFound[call.CallerComponent] = true
				}
				var foundCallerNames []string
				for name := range callersFound {
					foundCallerNames = append(foundCallerNames, fmt.Sprintf("'%s'", name))
				}
				return fmt.Sprintf("expected '%s' to be called by '%s', but it was called by %s instead.",
					cleanName, a.callerComponent, strings.Join(foundCallerNames, ", "))
			}

			// Otherwise, the error is about mismatched arguments.
			expectedArgsStr := "with any arguments"
			if len(a.expectedArgs) > 0 {
				expectedArgsStr = fmt.Sprintf("with arguments %v", a.expectedArgs)
			}

			var receivedCallsStr strings.Builder
			for i, call := range allCallsForFunc {
				if len(call.Params) == 0 {
					fmt.Fprintf(&receivedCallsStr, "\n    - Call %d: (no arguments)", i+1)
				} else {
					fmt.Fprintf(&receivedCallsStr, "\n    - Call %d: %v", i+1, call.Params)
				}
			}
			return fmt.Sprintf("expected '%s' to be called %d time(s) %s, but it was called 0 times with those arguments. %d call(s) were recorded with different arguments:%s",
				cleanName, a.times, expectedArgsStr, len(allCallsForFunc), receivedCallsStr.String())
		}
		return fmt.Sprintf("expected '%s' to be called %d time(s), but it was not called.", cleanName, a.times)
	}
	return fmt.Sprintf("expected '%s' to be called %d time(s), but it was called %d time(s)", cleanName, a.times, actualCount)
}

func (m *Spy) filterMatchingCalls(calls map[string][]*CallRecord, a *CalledFunc) []*CallRecord {
	recordedCalls, found := calls[a.funcName]
	if !found || len(recordedCalls) == 0 {
		return nil
	}

	// Start with all recorded calls for the function.
	matchingCalls := recordedCalls

	// If a specific caller is expected, filter by it first.
	if a.callerComponent != "" {
		matchingCalls = filterByCaller(matchingCalls, a.callerComponent)
	}

	// If specific arguments are expected, filter by them.
	if len(a.expectedArgs) > 0 {
		var paramMatchingCalls []*CallRecord
		for _, call := range matchingCalls {
			if paramsMatch(a.expectedArgs, call.Params) {
				paramMatchingCalls = append(paramMatchingCalls, call)
			}
		}
		matchingCalls = paramMatchingCalls
	}
	return matchingCalls
}

// filterByCaller filters a slice of CallRecords, returning only those made by the specified callerComponent.
func filterByCaller(calls []*CallRecord, callerComponent string) []*CallRecord {
	var filtered []*CallRecord
	for _, call := range calls {
		// call.CallerComponent is in the format "main.DogWalker"
		if call.CallerComponent == callerComponent {
			filtered = append(filtered, call)
		}
	}
	return filtered
}

func (m *Spy) consumeCall(calls map[string][]*CallRecord, a *CalledFunc) {
	allCalls := calls[a.funcName]
	for i, call := range allCalls {
		if paramsMatch(a.expectedArgs, call.Params) {
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

func splitFullFuncName(fullName string) (component, method string) {
	if fullName == "" {
		return "Unknown", "Unknown"
	}
	fullName = strings.TrimSuffix(fullName, "-fm")

	// Find the last dot, which separates the method name from the type.
	lastDotIndex := strings.LastIndex(fullName, ".")
	if lastDotIndex == -1 {
		return "Unknown", fullName // Should not happen with method calls
	}

	methodName := fullName[lastDotIndex+1:]
	componentPath := fullName[:lastDotIndex] // e.g., "github.com/user/project/main.(*DogStub)"

	// Find the last part of the path, which is the component name with package.
	lastSlashIndex := strings.LastIndex(componentPath, "/")
	componentWithPackage := componentPath[lastSlashIndex+1:] // e.g., "main.(*DogStub)"

	// Clean up the component name by removing pointer indicators and parentheses.
	componentName := strings.ReplaceAll(componentWithPackage, "(*", "")
	componentName = strings.ReplaceAll(componentName, ")", "")
	componentName = strings.ReplaceAll(componentName, "*", "")

	return componentName, methodName
}

// --- Matchers ---

type Matcher interface {
	Matches(x any) bool
	String() string
}
