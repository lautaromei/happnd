package main

import (
	"fmt"
	"strings"
)

const (
	// ANSI escape codes for styling console output.
	bold   = "\033[1m"
	red    = "\033[31m"
	yellow = "\033[33m"
	green  = "\033[32m"
	reset  = "\033[0m"
)

// DrawGraph generates a sequential, ASCII-based representation of the call graph.
func (m *Spy) DrawGraph(commonPackage string) string {
	m.RLock()
	defer m.RUnlock()

	if len(m.calls) == 0 {
		return "Call Graph: No calls recorded."
	}

	var finalBuilder strings.Builder
	if commonPackage != "" {
		finalBuilder.WriteString(fmt.Sprintf("Call Graph (package: %s):\n\n", commonPackage))
	} else {
		finalBuilder.WriteString("Call Graph:\n\n")
	}

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
			key := m.chainToString(chain, unexpectedSet, false, 1, commonPackage != "") // count is 1 for now
			if _, exists := chainCounts[key]; !exists {
				uniqueChainKeys = append(uniqueChainKeys, key)
			}
			chainCounts[key]++
		}

		// Draw the root node once.
		rootBox := m.formatNodeAsLines(rootName, nil, false, 1, commonPackage != "")
		arrow := " --> "

		for i, chainKey := range uniqueChainKeys {
			count := chainCounts[chainKey]
			// Re-render the chain with the correct count if it's repeated.
			chainStr := chainKey
			if count > 1 {
				// Find the original chain to re-render it. This is a bit inefficient but works.
				for _, chain := range chains {
					if m.chainToString(chain, unexpectedSet, false, 1, commonPackage != "") == chainKey {
						chainStr = m.chainToString(chain, unexpectedSet, false, count, commonPackage != "")
						break
					}
				}
			}

			chainLines := strings.Split(chainStr, "\n")
			rootPadding := strings.Repeat(" ", getVisibleLength(rootBox[1]))
			rootMidLineIndex := 1 // The middle line of a standard box is at index 1
			arrowPadding := strings.Repeat(" ", len(arrow))
			m.drawChain(&finalBuilder, rootBox, chainLines, arrow, rootPadding, arrowPadding, rootMidLineIndex, i == 0)
		}
	}

	return finalBuilder.String()
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

func (m *Spy) drawChain(builder *strings.Builder, rootBox, chainLines []string, arrow, rootPadding, arrowPadding string, rootMidLineIndex int, isFirstChain bool) {
	for lineIdx, line := range chainLines {
		currentArrow := arrowPadding
		if lineIdx == rootMidLineIndex {
			currentArrow = arrow
		}

		// For the first chain of a root, draw the root box completely.
		if isFirstChain {
			if lineIdx < len(rootBox) {
				builder.WriteString(fmt.Sprintf("%s%s%s\n", rootBox[lineIdx], currentArrow, line))
			} else {
				// If the chain part is taller than the root box.
				builder.WriteString(fmt.Sprintf("%s%s%s\n", rootPadding, currentArrow, line))
			}
		} else if lineIdx == rootMidLineIndex { // For subsequent chains, just draw the middle line with an arrow.
			builder.WriteString(fmt.Sprintf("%s%s%s\n", rootPadding, arrow, line))
		} else { // Top and bottom lines of boxes for subsequent chains.
			builder.WriteString(fmt.Sprintf("%s%s%s\n", rootPadding, arrowPadding, line))
		}
	}
}

func (m *Spy) chainToString(chain []*CallRecord, unexpectedSet map[*CallRecord]bool, drawRoot bool, count int, stripPackage bool) string {
	if len(chain) == 0 {
		return ""
	}

	var nodes []string
	var nodeParams [][]any

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
		isLastNode := (i == len(nodes)-1)
		params := nodeParams[i]
		boxLines := m.formatNodeAsLines(nodeName, params, isLastNode, count, stripPackage)
		lines = append(lines, boxLines)
		nodeWidths = append(nodeWidths, getVisibleLength(boxLines[1]))

		// If this node is the one that failed the assertion, add failure details.
		for _, failure := range m.failures {
			// Check if the current node in the graph matches the failed assertion.
			// This can be a direct name match or a parameter mismatch where the call itself is the one that failed.
			isParamMismatchNode := failure.mismatchedCall != nil &&
				fmt.Sprintf("%s.%s", failure.mismatchedCall.CalleeComponent, failure.mismatchedCall.CalleeMethod) == nodeName

			var isDirectFailureMatch bool
			if failure.failedAssertion.callerComponent != "" {
				// Match full "Component.Method" for assertions made with Struct().Called()
				expectedNodeName := fmt.Sprintf("%s.%s", failure.failedAssertion.callerComponent, failure.failedAssertion.funcName)
				isDirectFailureMatch = cleanFuncName(nodeName, stripPackage) == cleanFuncName(expectedNodeName, stripPackage)
			} else {
				// Match just "Method" for assertions made with Called()
				isDirectFailureMatch = strings.HasSuffix(cleanFuncName(nodeName, stripPackage), "."+failure.failedAssertion.funcName)
			}

			if isDirectFailureMatch || isParamMismatchNode {
				reason := failure.reason
				isArgMismatch := strings.Contains(reason, "different arguments")
				isCallerMismatch := strings.Contains(reason, "called by")
				isCountMismatch := !isArgMismatch && !isCallerMismatch && strings.Contains(reason, "time(s)")

				var actualCaller string
				if isCallerMismatch {
					// Find the actual call record to get the real caller
					for _, call := range m.calls {
						if call.CalleeMethod == failure.failedAssertion.funcName {
							actualCaller = call.CallerComponent
							break
						}
					}
				}

				// Re-format the node to show expected vs actual.
				lines[i] = m.formatNodeAsLinesWithFailure(nodeName, failure, params, isArgMismatch, isCallerMismatch, isCountMismatch, actualCaller, stripPackage)
				break // A node can only have one failure annotation.
			}
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

func (m *Spy) formatNodeAsLines(name string, params []any, isLastNode bool, count int, stripPackage bool) []string {
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

	// The user wants to see only the method name in bold for successful calls.
	// We need to check if this node is associated with any failure.
	isFailureNode := false
	for _, failure := range m.failures {
		if cleanFuncName(name, stripPackage) == cleanFuncName(failure.failedAssertion.funcName, stripPackage) {
			isFailureNode = true
			break
		}
	}

	multiplier := ""
	if isLastNode && count > 1 {
		multiplier = fmt.Sprintf(" (%sx%d%s)", yellow, count, reset)
	}

	content := fmt.Sprintf("%s%s%s", name, paramsStr, multiplier) // name might already be bold
	width := getVisibleLength(content) + 2                        // +2 for padding

	// If it's not a failure node and not an unexpected call, bold just the method name.
	if !isFailureNode && !strings.HasPrefix(name, bold) {
		// Split "Struct.Method" into "Struct" and "Method"
		structAndMethod := cleanFuncName(name, stripPackage)
		lastDot := strings.LastIndex(structAndMethod, ".")
		structName := structAndMethod[:lastDot+1] // "Struct."
		methodName := structAndMethod[lastDot+1:] // "Method"

		content = fmt.Sprintf("%s%s%s%s%s%s", structName, bold, methodName, reset, paramsStr, multiplier)
		width = getVisibleLength(content) + 2
	}
	topLine := "." + strings.Repeat("-", width) + "." // Recalculate width in case content changed
	middleLine := fmt.Sprintf("| %s |", content)
	bottomLine := "." + strings.Repeat("-", width) + "."

	return []string{topLine, middleLine, bottomLine}
}

func (m *Spy) formatNodeAsLinesWithFailure(name string, failure *failureRecord, actualParams []any, isArgMismatch, isCallerMismatch, isCountMismatch bool, actualCaller string, stripPackage bool) []string {
	assertion := failure.failedAssertion
	expectedParamsStr := formatArgs(assertion.expectedArgs)
	actualStr := formatArgs(actualParams)

	var content string
	cleanNodeName := cleanFuncName(name, stripPackage)
	if isCallerMismatch {
		// Format: MyFunc(expected caller: A, actual: B)
		content = fmt.Sprintf("%s(expected caller: %s, %sactual: %s%s)", cleanNodeName, assertion.callerComponent, green, actualCaller, reset)
	} else if isArgMismatch {
		// Format: MyFunc(expected: [1], actual: [2])
		// The "actual" part will be colored green.
		content = fmt.Sprintf("%s(expected: %s, %sactual: %s%s)", cleanNodeName, expectedParamsStr, green, actualStr, reset)
	} else if isCountMismatch {
		// Format: MyFunc(expected: 2, actual: 1)
		content = fmt.Sprintf("%s(%sexpected: x%d%s, %sactual: x%d%s)", cleanNodeName, red, assertion.times, reset, green, failure.actualCount, reset)
	} else {
		// Handle other failures, like wrong call count (e.g., Times(2) but called 1 time).
		// The box will be red, indicating a failure on this node.
		// This is a fallback, but isCountMismatch should catch most cases. Use the already cleaned name.
		content = fmt.Sprintf("%s(%sexpected: x%d%s, %sactual: x%d%s)", cleanNodeName, red, assertion.times, reset, green, failure.actualCount, reset)
	}

	width := getVisibleLength(content) + 2 // +2 for padding
	topLine := "." + strings.Repeat("-", width) + "."
	middleLine := fmt.Sprintf("| %s%s%s%s |", bold, red, content, reset) // The whole box is red and bold
	bottomLine := "." + strings.Repeat("-", width) + "."

	return []string{topLine, middleLine, bottomLine}
}

// getVisibleLength calculates the visible length of a string by stripping ANSI codes.
func getVisibleLength(s string) int {
	// A simple way to strip ANSI codes is to remove them with a regex,
	// but for this specific case, we can just replace the known codes.
	s = strings.ReplaceAll(s, green, "")
	s = strings.ReplaceAll(s, bold, "")
	s = strings.ReplaceAll(s, red, "")
	s = strings.ReplaceAll(s, reset, "")
	s = strings.ReplaceAll(s, yellow, "")
	return len(s)
}
