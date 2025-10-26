package happnd

import (
	"fmt"
	"path"
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
	CalleeFile      string
	CalleeFileName  string // Just the filename
	CalleeLine      int
	Params          []any
}

// failureRecord stores information about a failed assertion.
type failureRecord struct {
	failedAssertion *CalledFunc
	reason          string
	actualCount     int // Add actual count for better graph annotations
	mismatchedCall  *CallRecord
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

	// Get just the filename from the full path
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
		CalleeFile:      calleeFrame.File,
		CalleeFileName:  path.Base(calleeFrame.File),
		CalleeLine:      calleeFrame.Line,
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

		// Check if all calls belong to the same package to simplify the graph.
		commonPackage, allSame := m.checkAndGetCommonPackage()
		var graph string
		if allSame {
			graph = m.DrawGraph(commonPackage)
		} else {
			graph = m.DrawGraph("") // Pass empty string if packages are mixed
		}
		errorReport := fmt.Sprintf("\nfound %d error(s) during expectation assertion:\n- %s", len(errs), strings.Join(errs, "\n- "))
		return false, fmt.Errorf("%s%s", graph, errorReport)
	}

	return true, nil
}

// checkAndGetCommonPackage iterates through all recorded calls to see if they share a single common package.
func (m *Spy) checkAndGetCommonPackage() (string, bool) {
	if len(m.calls) == 0 {
		return "", true // No calls, so vacuously true.
	}

	var commonPackage string

	// Helper to extract package from a component name like "main.MyStruct"
	getPackage := func(componentName string) string {
		parts := strings.Split(componentName, ".")
		if len(parts) > 1 {
			return parts[0]
		}
		return "" // No package found
	}

	commonPackage = getPackage(m.calls[0].CalleeComponent)

	for _, call := range m.calls {
		if getPackage(call.CalleeComponent) != commonPackage || getPackage(call.CallerComponent) != commonPackage {
			return "", false // Found a different package
		}
	}
	return commonPackage, true
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

		allCallsForFunc := calls[assertion.funcName]
		matchingCalls := m.filterMatchingCalls(allCallsForFunc, assertion)
		actualCount := len(matchingCalls)

		if actualCount != assertion.times {
			// For error reporting, get all calls for this function name from the original map.
			errMsg := m.buildMismatchedCallError(assertion, actualCount, allCallsForFunc)
			errs = append(errs, errMsg)
			m.addFailure(assertion, errMsg, actualCount, allCallsForFunc)
			// If the function was called but with the wrong parameters,
			// consume those calls to prevent them from being reported as "unexpected".
			if actualCount == 0 && len(allCallsForFunc) > 0 {
				delete(calls, assertion.funcName)
			} else if actualCount > 0 {
				// Consume the calls that did match to prevent them from being reported as unexpected,
				// even though the count was wrong.
				delete(calls, assertion.funcName)
			}
		} else { // actualCount == assertion.times
			// Consume the verified calls from the main map
			m.consumeMatchingCalls(calls, assertion.funcName, matchingCalls)
		}
	}
	return errs
}

func (m *Spy) addFailure(a *CalledFunc, reason string, actualCount int, allCallsForFunc []*CallRecord) {
	failure := &failureRecord{
		failedAssertion: a,
		reason:          reason,
		actualCount:     actualCount,
	}
	// If it's a parameter mismatch, find the first call that was mismatched to annotate it in the graph.
	if actualCount == 0 && len(allCallsForFunc) > 0 {
		failure.mismatchedCall = allCallsForFunc[0]
	}

	m.failures = append(m.failures, failure)
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
				callLocation := fmt.Sprintf("%s:%d", call.CalleeFileName, call.CalleeLine)
				nodeName := fmt.Sprintf("%s.%s", call.CalleeComponent, call.CalleeMethod)
				callStr := fmt.Sprintf("%s: %s%sunexpected call: %s%s%s", callLocation, bold, red, nodeName, formatArgs(call.Params), reset)
				unexpectedDetails = append(unexpectedDetails, callStr)
				m.unexpectedCalls = append(m.unexpectedCalls, call)
			}
		}
	}
	if unexpectedCount > 0 {
		return fmt.Errorf("found %d unexpected call(s):\n- %s", unexpectedCount, strings.Join(unexpectedDetails, "\n- "))
	}
	return nil
}

// buildMismatchedCallError creates a detailed error message for a failed assertion.
func (m *Spy) buildMismatchedCallError(a *CalledFunc, actualCount int, allRecordedCallsForFunc []*CallRecord) string {
	cleanName := a.funcName // We don't clean it here to keep package info for the text error
	if actualCount == 0 {
		if len(allRecordedCallsForFunc) > 0 {
			// If a specific caller was expected, the error is about the caller mismatch.
			if a.callerComponent != "" {
				callersFound := make(map[string]bool)
				var firstMismatchLocation string
				for _, call := range allRecordedCallsForFunc {
					// Only consider calls that would have otherwise matched on parameters
					if paramsMatch(a.expectedArgs, call.Params) {
						callersFound[call.CallerComponent] = true
					}
				}
				if len(callersFound) > 0 {
					// Find the location of the first call that caused this mismatch
					for _, call := range allRecordedCallsForFunc {
						if paramsMatch(a.expectedArgs, call.Params) {
							firstMismatchLocation = fmt.Sprintf("%s:%d: ", call.CalleeFileName, call.CalleeLine)
							break
						}
					}
					var foundCallerNames []string
					for name := range callersFound {
						foundCallerNames = append(foundCallerNames, fmt.Sprintf("'%s'", name))
					}
					return fmt.Sprintf("%sexpected '%s' to be called by '%s', but it was called by %s instead.", firstMismatchLocation, cleanName, a.callerComponent, strings.Join(foundCallerNames, ", "))
				}
			}
			// Otherwise, the error is about mismatched arguments.
			expectedArgsStr := "with any arguments"
			if len(a.expectedArgs) > 0 {
				expectedArgsStr = fmt.Sprintf("with arguments %v", a.expectedArgs)
			}

			var receivedCallsStr strings.Builder
			for i, call := range allRecordedCallsForFunc {
				if len(call.Params) == 0 {
					fmt.Fprintf(&receivedCallsStr, "\n    - Call %d: (no arguments)", i+1)
				} else {
					fmt.Fprintf(&receivedCallsStr, "\n    - Call %d: %v", i+1, call.Params)
				}
			}
			// Prepend the location of the first recorded call for this function.
			location := fmt.Sprintf("%s:%d: ", allRecordedCallsForFunc[0].CalleeFileName, allRecordedCallsForFunc[0].CalleeLine)
			return fmt.Sprintf("%sexpected '%s' to be called %d time(s) %s, but it was called 0 times with those arguments. %d call(s) were recorded with different arguments:%s", location, cleanName, a.times, expectedArgsStr, len(allRecordedCallsForFunc), receivedCallsStr.String())
		}
		return fmt.Sprintf("expected '%s' to be called %d time(s), but it was not called.", cleanName, a.times)
	}
	// For call count mismatches, point to the first call.
	location := fmt.Sprintf("%s:%d: ", allRecordedCallsForFunc[0].CalleeFileName, allRecordedCallsForFunc[0].CalleeLine)
	return fmt.Sprintf("%sexpected '%s' to be called %d time(s), but it was called %d time(s)", location, cleanName, a.times, actualCount)
}

func (m *Spy) filterMatchingCalls(recordedCalls []*CallRecord, a *CalledFunc) []*CallRecord {
	if len(recordedCalls) == 0 {
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

func (m *Spy) consumeMatchingCalls(allCalls map[string][]*CallRecord, funcName string, callsToConsume []*CallRecord) {
	if len(callsToConsume) == 0 {
		return
	}

	// Create a set of pointers for quick lookup of calls to consume.
	consumeSet := make(map[*CallRecord]bool, len(callsToConsume))
	for _, call := range callsToConsume {
		consumeSet[call] = true
	}

	// Get the original slice of calls for this function.
	originalCalls := allCalls[funcName]
	// Create a new slice to hold the calls that are not consumed.
	var remainingCalls []*CallRecord
	for _, call := range originalCalls {
		if !consumeSet[call] {
			remainingCalls = append(remainingCalls, call)
		}
	}

	allCalls[funcName] = remainingCalls
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

func cleanFuncName(fullName string, stripPackage bool) string {
	fullName = strings.TrimSuffix(fullName, "-fm")
	if stripPackage {
		parts := strings.Split(fullName, ".")
		if len(parts) > 1 {
			return strings.Join(parts[1:], ".") // Keep struct and method, remove package
		}
	}
	return fullName
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

	// Keep the component name with package, but clean up pointer indicators.
	componentWithPackage = strings.ReplaceAll(componentWithPackage, "(*", "")
	componentWithPackage = strings.ReplaceAll(componentWithPackage, ")", "")
	return componentWithPackage, methodName
}

// --- Matchers ---

type Matcher interface {
	Matches(x any) bool
	String() string
}
