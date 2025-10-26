package main

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"sync"
)

const Anything = "*"

const (
	// ANSI escape codes for styling console output.
	bold  = "\033[1m"
	red   = "\033[31m"
	reset = "\033[0m"
)

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
	m.lastFailure = nil
	m.calls = make([]*CallRecord, 0)
	m.unexpectedCalls = nil
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

	var finalBuilder strings.Builder
	finalBuilder.WriteString("Call Graph:\n\n")

	// Group chains by their root caller to avoid duplicating the source node.
	chainsByRoot := m.groupChainsByRoot()

	for rootName, chains := range chainsByRoot {
		// Create a set of unexpected calls for quick lookup.
		unexpectedSet := make(map[*CallRecord]bool)
		if m.unexpectedCalls != nil {
			for _, uc := range m.unexpectedCalls {
				unexpectedSet[uc] = true
			}
		}

		// Count identical chains to keep the output clean
		chainCounts := make(map[string]int)
		uniqueChainKeys := make([]string, 0)
		for _, chain := range chains {
			// We pass `false` for `drawRoot` because we will draw it manually once.
			key := m.chainToString(chain, unexpectedSet, false)
			if _, exists := chainCounts[key]; !exists {
				uniqueChainKeys = append(uniqueChainKeys, key)
			}
			chainCounts[key]++
		}

		// Draw the root node once.
		rootBox := m.formatNodeAsLines(rootName, nil)
		arrow := " --> "

		for i, key := range uniqueChainKeys {
			chainLines := strings.Split(key, "\n")
			rootPadding := strings.Repeat(" ", getVisibleLength(rootBox[1]))
			rootMidLineIndex := 1 // The middle line of a standard box is at index 1
			arrowPadding := strings.Repeat(" ", len(arrow))

			for lineIdx, line := range chainLines {
				currentArrow := arrowPadding
				if lineIdx == rootMidLineIndex {
					currentArrow = arrow
				}
				// For the first chain, draw the root box completely.
				if i == 0 {
					if lineIdx < len(rootBox) {
						finalBuilder.WriteString(fmt.Sprintf("%s%s%s\n", rootBox[lineIdx], currentArrow, line))
					} else {
						finalBuilder.WriteString(fmt.Sprintf("%s%s%s\n", rootPadding, currentArrow, line))
					}
				} else if lineIdx == rootMidLineIndex { // For subsequent chains, just draw the middle line with an arrow from the root's vertical space.
					finalBuilder.WriteString(fmt.Sprintf("%s%s%s\n", rootPadding, arrow, line))
				} else { // Top and bottom lines of boxes
					finalBuilder.WriteString(fmt.Sprintf("%s%s%s\n", rootPadding, arrowPadding, line))
				}
			}
			count := chainCounts[key]
			if count > 1 {
				finalBuilder.WriteString(fmt.Sprintf("%s%s(repeated %d times)\n", rootPadding, strings.Repeat(" ", len(arrow)), count))
			}
		}
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
	builder.WriteString(fmt.Sprintf("%s(X) \n", expectedBoxLines[1]))
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

func (m *Spy) groupChainsByRoot() map[string][][]*CallRecord {
	chains := m.buildCallChains()
	grouped := make(map[string][][]*CallRecord)

	for _, chain := range chains {
		if len(chain) > 0 {
			rootCall := chain[0]
			rootName := fmt.Sprintf("%s.%s", rootCall.CallerComponent, rootCall.CallerMethod)
			grouped[rootName] = append(grouped[rootName], chain)
		}
	}
	return grouped
}

func (m *Spy) buildCallChains() [][]*CallRecord {
	chains := [][]*CallRecord{}
	visited := make(map[*CallRecord]bool)

	// Identify root calls (calls made from a test function)
	var rootCalls []*CallRecord
	for _, call := range m.calls {
		if strings.HasPrefix(call.CallerMethod, "Test") {
			rootCalls = append(rootCalls, call)
		}
	}

	// If no direct test calls, treat all calls as potential roots
	if len(rootCalls) == 0 {
		rootCalls = m.calls
	}

	for _, rootCall := range rootCalls {
		if visited[rootCall] {
			continue
		}

		chain := []*CallRecord{rootCall}
		visited[rootCall] = true
		current := rootCall

		// Find the next call in the sequence
		for i := 0; i < len(m.calls); i++ {
			nextCall := m.calls[i]
			if !visited[nextCall] && nextCall.CallerComponent == current.CalleeComponent && nextCall.CallerMethod == current.CalleeMethod {
				chain = append(chain, nextCall)
				visited[nextCall] = true
				current = nextCall
				i = -1 // Restart search for the next link
			}
		}
		chains = append(chains, chain)
	}
	return chains
}

func (m *Spy) chainToString(chain []*CallRecord, unexpectedSet map[*CallRecord]bool, drawRoot bool) string {
	if len(chain) == 0 {
		return ""
	}

	var nodes []string
	var nodeParams [][]any

	// Check if there's a failure to annotate in the graph
	var failureAnnotation *failureRecord
	if m.lastFailure != nil {
		failureAnnotation = m.lastFailure
	}

	// The first node is the caller of the first call in the chain.
	if drawRoot {
		firstCall := chain[0]
		callerName := fmt.Sprintf("%s.%s", firstCall.CallerComponent, firstCall.CallerMethod)
		nodes = append(nodes, callerName)
		nodeParams = append(nodeParams, nil) // The initial caller has no recorded params.

	}
	// Then, add all the subsequent callees.
	for _, call := range chain {
		isUnexpected := unexpectedSet[call]
		calleeName := fmt.Sprintf("%s.%s", call.CalleeComponent, call.CalleeMethod)
		nodes = append(nodes, calleeName)
		nodeParams = append(nodeParams, call.Params)

		if isUnexpected {
			nodes[len(nodes)-1] = fmt.Sprintf("%s%s%s%s", bold, red, nodes[len(nodes)-1], reset)
		}
	}

	var lines [][]string
	var nodeWidths []int

	for i, nodeName := range nodes {
		params := nodeParams[i]
		boxLines := m.formatNodeAsLines(nodeName, params)
		lines = append(lines, boxLines)
		nodeWidths = append(nodeWidths, getVisibleLength(boxLines[1]))

		// If this node is the one that failed the assertion, add failure details.
		if failureAnnotation != nil && i > 0 && strings.Contains(nodeName, failureAnnotation.failedAssertion.funcName) {
			var failureText string
			expectedCaller := failureAnnotation.failedAssertion.callerComponent
			// Check if the failure was due to a caller mismatch.
			if expectedCaller != "" {
				actualCaller := chain[i-1].CallerComponent
				failureText = fmt.Sprintf("expected caller '%s', but was '%s'", expectedCaller, actualCaller)
			} else {
				// Otherwise, it's an argument mismatch.
				expectedArgsStr := formatArgs(failureAnnotation.failedAssertion.expectedArgs)
				actualArgsStr := formatArgs(params)
				failureText = fmt.Sprintf("it expected %s, got %s", expectedArgsStr, actualArgsStr)
			}

			// Add the failure annotation as a new line below the box.

			// Calculate padding to center the annotation under its box.
			boxWidth := nodeWidths[i]
			annotationWidth := len(failureText)
			padding := (boxWidth - annotationWidth) / 2
			if padding < 0 {
				padding = 0
			}
			paddingStr := strings.Repeat(" ", padding)
			lines[i] = append(lines[i], fmt.Sprintf("%s%s%s%s%s", paddingStr, bold, red, failureText, reset))
		}
	}

	// Assemble the final graph string, line by line.
	var result strings.Builder
	maxLines := 0
	for _, lineSet := range lines {
		if len(lineSet) > maxLines {
			maxLines = len(lineSet)
		}
	}

	for lineIdx := 0; lineIdx < maxLines; lineIdx++ {
		for nodeIdx, lineSet := range lines {
			if lineIdx < len(lineSet) {
				result.WriteString(lineSet[lineIdx])
			} else {
				result.WriteString(strings.Repeat(" ", nodeWidths[nodeIdx]))
			}

			if nodeIdx < len(lines)-1 {
				arrow := " --> "
				if lineIdx == 1 { // Middle line of the box
					result.WriteString(arrow)
				} else {
					result.WriteString(strings.Repeat(" ", len(arrow)))
				}
			}
		}
		if lineIdx < maxLines-1 {
			result.WriteString("\n")
		}
	}

	return result.String()
}

// formatArgs is a helper to display arguments, showing "(no arguments)" for empty slices.
func formatArgs(args []any) string {
	if len(args) == 0 {
		return "(no arguments)"
	}
	return fmt.Sprintf("%v", args)
}

func (m *Spy) formatNodeAsLines(name string, params []any) []string {
	var paramsStr string
	if params != nil {
		var paramParts []string
		isBold := strings.HasPrefix(name, bold)

		for _, p := range params {
			// If the node is bold, make the params bold too.
			if isBold {
				paramParts = append(paramParts, fmt.Sprintf("%s%s%v%s", bold, red, p, reset))
			} else {
				paramParts = append(paramParts, fmt.Sprintf("%v", p))
			}
		}
		if len(paramParts) > 0 {
			// The comma and parentheses should also be bold if the content is.
			if isBold {
				paramsStr = fmt.Sprintf("%s%s(%s)%s", bold, red, strings.Join(paramParts, ", "), reset)
			} else {
				paramsStr = fmt.Sprintf("(%s)", strings.Join(paramParts, ", "))
			}
		}
	}

	content := fmt.Sprintf("%s%s", name, paramsStr) // name might already be bold
	width := getVisibleLength(content) + 2          // +2 for padding
	topLine := "." + strings.Repeat("-", width) + "."
	middleLine := fmt.Sprintf("| %s |", content)
	bottomLine := "." + strings.Repeat("-", width) + "."

	return []string{topLine, middleLine, bottomLine}
}

// getVisibleLength calculates the visible length of a string by stripping ANSI codes.
func getVisibleLength(s string) int {
	// A simple way to strip ANSI codes is to remove them with a regex,
	// but for this specific case, we can just replace the known codes.
	s = strings.ReplaceAll(s, bold, "")
	s = strings.ReplaceAll(s, red, "")
	s = strings.ReplaceAll(s, reset, "")
	return len(s)
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
	firstFailureSet := false

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
			if !firstFailureSet {
				m.lastFailure = &failureRecord{failedAssertion: assertion, reason: errMsg}
				firstFailureSet = true
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
func (m *Spy) checkUnexpectedCalls(calls map[string][]*CallRecord) error {
	unexpectedCount := 0
	m.unexpectedCalls = make([]*CallRecord, 0)
	var unexpectedDetails []string
	for _, remainingCalls := range calls {
		if len(remainingCalls) > 0 {
			for _, call := range remainingCalls {
				unexpectedCount++
				nodeName := fmt.Sprintf("%s.%s", call.CalleeComponent, call.CalleeMethod)
				boxLines := m.formatNodeAsLines(nodeName, call.Params)
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
