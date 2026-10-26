package main

import (
	"fmt"
	"strings"
)

type authzServer struct {
	name      string
	scenarios map[string]string // name -> controls; "default" applies to every check
	quiet     bool              // suppress all per-request logging
	metrics   *checkMetrics     // nil disables metrics
}

// decisionFor merges the controls from all carriers of the check. Invalid controls
// deny with 400; the reason is in decision.invalid.
func (s *authzServer) decisionFor(info checkRequestInfo) decision {
	carriers := []carrier{
		{carrierDefault, s.scenarios[carrierDefault]},
		{carrierContext, info.contextExtension(controlName)},
		{carrierQuery, queryControls(info.request.Path)},
		{carrierHeader, strings.Join(info.request.Headers[controlName], " ")},
		{carrierAuthorization, authorizationControls(info.header("authorization"))},
	}
	controls, err := mergeControls(carriers, s.scenarios)
	if err != nil {
		return invalidDecision(controls, "", err)
	}
	d, err := decide(controls)
	if err != nil {
		return invalidDecision(controls, d.tag, err)
	}
	return d
}

// validateScenarios checks the scenarios at startup, so that checks can expand them without errors.
func validateScenarios(scenarios map[string]string) error {
	for name, text := range scenarios {
		if name == "" || strings.ContainsAny(name, " ,=") {
			return fmt.Errorf("scenario %q: name must be nonempty without spaces, commas or '='", name)
		}
		controls, err := parseControls(text)
		if err != nil {
			return fmt.Errorf("scenario %q: %w", name, err)
		}
		for _, c := range controls {
			if c.key == "scenario" {
				return fmt.Errorf("scenario %q: scenarios cannot refer to other scenarios", name)
			}
		}
		merged, _ := mergeControls([]carrier{{carrierScenario, text}}, nil)
		if _, err := decide(merged); err != nil {
			return fmt.Errorf("scenario %q: %w", name, err)
		}
	}
	return nil
}
