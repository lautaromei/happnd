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
}

type Spy struct {
	calls       []*CallRecord
	lastFailure *failureRecord // Stores info about the last failed expectation.
	sync.RWMutex
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
	m.lastFailure = nil
	m.calls = make([]*CallRecord, 0)
}

func (m *Spy) TotalCalls() int {
	m.RLock()
	defer m.RUnlock()
	return len(m.calls)
}

// DrawGraph generates a sequential, ASCII-based representation of the call graph.
func (m *Spy) DrawGraph() string {
	m.RLock()
	defer m.RUnlock()

	if len(m.calls) == 0 {
		return "Call Graph: No calls recorded.\n"
	}

	// Build chains of calls
	chains := m.buildCallChains()

	// Count identical chains to keep the output clean
	chainCounts := make(map[string]int)
	uniqueChainKeys := make([]string, 0)
	for _, chain := range chains {
		key := m.chainToString(chain)
		if _, exists := chainCounts[key]; !exists {
			uniqueChainKeys = append(uniqueChainKeys, key)
		}
		chainCounts[key]++
	}

	var finalBuilder strings.Builder
	finalBuilder.WriteString("Call Graph:\n\n")

	for _, key := range uniqueChainKeys {
		count := chainCounts[key]
		if count > 1 {
			finalBuilder.WriteString(fmt.Sprintf("%s\n(repeated %d times)\n\n", key, count))
		} else {
			finalBuilder.WriteString(fmt.Sprintf("%s\n\n", key))
		}
	}

	// If an assertion failed, add a detailed failure box to the graph.
	if m.lastFailure != nil {
		finalBuilder.WriteString("\n--- Assertion Failure Details ---\n")
		finalBuilder.WriteString(m.drawFailureDetails())
	}

	return finalBuilder.String()
}

// drawFailureDetails generates a text box explaining what was expected vs. what actually happened.
func (m *Spy) drawFailureDetails() string {
	var builder strings.Builder
	failedAssertion := m.lastFailure.failedAssertion
	reason := m.lastFailure.reason

	// --- Expected Call ---
	builder.WriteString("Expected call:\n")
	expectedNodeName := cleanFuncName(failedAssertion.funcName)
	expectedBoxLines := m.formatNodeAsLines(expectedNodeName, failedAssertion.expectedArgs)

	// Draw the expected box, but "crossed out" to indicate failure.
	builder.WriteString(strings.ReplaceAll(expectedBoxLines[0], "-", "~"))
	builder.WriteString("\n")
	builder.WriteString(fmt.Sprintf("%s  <-- (X) FAILED\n", expectedBoxLines[1]))
	builder.WriteString(strings.ReplaceAll(expectedBoxLines[2], "-", "~"))
	builder.WriteString("\n")
	builder.WriteString(fmt.Sprintf("Reason: %s\n", reason))

	// --- Actual Call (if applicable) ---
	// Find an actual call with the same method name to show for comparison.
	if strings.Contains(reason, "but it was called 0 times with those arguments") {
		var actualCall *CallRecord
		for _, call := range m.calls {
			if call.CalleeMethod == expectedNodeName {
				actualCall = call
				break
			}
		}

		if actualCall != nil {
			builder.WriteString("\nActual call found:\n")
			actualNodeName := fmt.Sprintf("%s.%s", actualCall.CalleeComponent, actualCall.CalleeMethod)
			actualBoxLines := m.formatNodeAsLines(actualNodeName, actualCall.Params)
			actualBoxLines[1] = fmt.Sprintf("%s  <-- (+) ACTUAL", actualBoxLines[1])
			builder.WriteString(strings.Join(actualBoxLines, "\n"))
			builder.WriteString("\n")
		}
	}

	return builder.String()
}

func (m *Spy) buildCallChains() [][]*CallRecord {
	var chains [][]*CallRecord
	if len(m.calls) == 0 {
		return chains
	}

	// Group calls by their direct caller to handle sequences like A->B, A->C
	callsByCaller := make(map[string][]*CallRecord)
	for _, call := range m.calls {
		callerID := fmt.Sprintf("%s.%s", call.CallerComponent, call.CallerMethod)
		callsByCaller[callerID] = append(callsByCaller[callerID], call)
	}

	// Find the root calls (those initiated by the test itself or an un-spied function)
	calleeSet := make(map[string]bool)
	for _, call := range m.calls {
		calleeID := fmt.Sprintf("%s.%s", call.CalleeComponent, call.CalleeMethod)
		calleeSet[calleeID] = true
	}

	for callerID, callGroup := range callsByCaller {
		if _, ok := calleeSet[callerID]; !ok {
			// This caller was never a callee, so it's a root of a chain.
			chains = append(chains, callGroup)
		}
	}

	// Fallback for cases where the root is not easily identifiable (e.g., everything is spied)
	if len(chains) == 0 && len(m.calls) > 0 {
		return [][]*CallRecord{m.calls}
	}

	return chains
}

func (m *Spy) chainToString(chain []*CallRecord) string {
	if len(chain) == 0 {
		return ""
	}

	var nodes []string
	var nodeParams [][]any

	// The first node is the caller of the first call in the chain.
	firstCall := chain[0]
	callerName := fmt.Sprintf("%s.%s", firstCall.CallerComponent, firstCall.CallerMethod)
	nodes = append(nodes, callerName)
	nodeParams = append(nodeParams, nil) // The initial caller has no recorded params.

	// Then, add all the subsequent callees.
	for _, call := range chain {
		calleeName := fmt.Sprintf("%s.%s", call.CalleeComponent, call.CalleeMethod)
		nodes = append(nodes, calleeName)
		nodeParams = append(nodeParams, call.Params)
	}

	var top, middle, bottom strings.Builder
	for i, nodeName := range nodes {
		boxLines := m.formatNodeAsLines(nodeName, nodeParams[i])
		top.WriteString(boxLines[0])

		middleLine := boxLines[1]
		middle.WriteString(middleLine)

		bottom.WriteString(boxLines[2])

		// If it's not the last node, add a connecting arrow.
		if i < len(nodes)-1 {
			arrow := " --> "
			top.WriteString(strings.Repeat(" ", len(arrow)))
			middle.WriteString(arrow)
			bottom.WriteString(strings.Repeat(" ", len(arrow)))
		}
	}

	return fmt.Sprintf("%s\n%s\n%s", top.String(), middle.String(), bottom.String())
}

func (m *Spy) formatNodeAsLines(name string, params []any) []string {
	var paramsStr string
	if params != nil {
		var paramParts []string
		for _, p := range params {
			paramParts = append(paramParts, fmt.Sprintf("%v", p))
		}
		if len(paramParts) > 0 {
			paramsStr = fmt.Sprintf("(%s)", strings.Join(paramParts, ", "))
		}
	}

	content := fmt.Sprintf("%s%s", name, paramsStr)
	width := len(content) + 2 // +2 for padding
	topLine := "." + strings.Repeat("-", width) + "."
	middleLine := fmt.Sprintf("| %s |", content)
	bottomLine := "'" + strings.Repeat("-", width) + "'"

	return []string{topLine, middleLine, bottomLine}
}

func (m *Spy) Happened(that ...*CalledFunc) (bool, error) {
	m.RLock()
	defer m.RUnlock()

	// Group recorded calls by function name for efficient lookup.
	callsByFunc := make(map[string][][]any)
	for _, call := range m.calls {
		funcName := call.CalleeMethod
		callsByFunc[funcName] = append(callsByFunc[funcName], call.Params)
	}

	// Create a mutable copy of the grouped calls to work with.
	copiedCalls := make(map[string][][]any, len(callsByFunc))
	for funcName, calls := range callsByFunc {
		callsCopy := make([][]any, len(calls))
		copy(callsCopy, calls)
		copiedCalls[funcName] = callsCopy
	}

	errs := m.verifyExpectations(copiedCalls, callsByFunc, that)

	if unexpectedErr := m.checkUnexpectedCalls(copiedCalls); unexpectedErr != nil {
		errs = append(errs, unexpectedErr.Error())
	}

	if len(errs) > 0 {
		// On failure, generate the graph and include it in the error.
		errorReport := fmt.Sprintf("found %d error(s) during expectation assertion:\n- %s\n\n", len(errs), strings.Join(errs, "\n- "))
		graph := m.DrawGraph()
		return false, fmt.Errorf("%s%s", errorReport, graph)
	}

	return true, nil
}

// verifyExpectations checks each assertion against the recorded calls, consuming them if they match.
func (m *Spy) verifyExpectations(calls, originalCalls map[string][][]any, assertions []*CalledFunc) []string {
	var errs []string
	firstFailureSet := false

	setFailure := func(assertion *CalledFunc, reason string) {
		m.lastFailure = &failureRecord{failedAssertion: assertion, reason: reason}
		firstFailureSet = true
	}

	for _, assertion := range assertions {
		if assertion.err != nil {
			errs = append(errs, assertion.err.Error())
			continue
		}

		matchingCalls := m.filterMatchingCalls(calls, assertion)
		actualCount := len(matchingCalls)

		if actualCount != assertion.times {
			allCallsForFunc := originalCalls[assertion.funcName] // Use original calls for error reporting
			errMsg := m.buildMismatchedCallError(assertion, actualCount, allCallsForFunc)
			errs = append(errs, errMsg)
			if !firstFailureSet {
				setFailure(assertion, errMsg)
			}
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
func (m *Spy) buildMismatchedCallError(a *CalledFunc, actualCount int, allCallsForFunc [][]any) string {
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
				cleanFuncName(a.funcName), a.times, expectedArgsStr, len(allCallsForFunc), receivedCallsStr.String())
		}
		return fmt.Sprintf("expected '%s' to be called %d time(s), but it was not called.", a.funcName, a.times)
	}
	return fmt.Sprintf("expected '%s' to be called %d time(s), but it was called %d time(s)", a.funcName, a.times, actualCount)
}

func (m *Spy) filterMatchingCalls(calls map[string][][]any, a *CalledFunc) [][]any {
	recordedCalls, found := calls[a.funcName]
	if !found || len(recordedCalls) == 0 {
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

func (m *Spy) consumeCall(calls map[string][][]any, a *CalledFunc) {
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

func splitFullFuncName(fullName string) (component, method string) {
	if fullName == "" {
		return "Unknown", "Unknown"
	}
	fullName = strings.TrimSuffix(fullName, "-fm")
	parts := strings.Split(fullName, ".")
	methodName := parts[len(parts)-1]
	componentPath := strings.Join(parts[:len(parts)-1], ".")
	componentParts := strings.Split(componentPath, "/")
	return strings.TrimPrefix(strings.TrimPrefix(componentParts[len(componentParts)-1], "("), "*"), methodName
}

// --- Matchers ---

type Matcher interface {
	Matches(x any) bool
	String() string
}
