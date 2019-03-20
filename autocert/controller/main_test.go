package main

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
)

func TestShouldMutate(t *testing.T) {
	testCases := []struct {
		description string
		subject string
		namespace string
		expected bool
	} {
		{ "full cluster domain", "test.default.svc.cluster.local", "default", true },
		{ "full cluster domain wrong ns", "test.default.svc.cluster.local", "kube-system", false },
		{ "left dots get stripped", ".test.default.svc.cluster.local", "default", true },
		{ "left dots get stripped wrong ns", ".test.default.svc.cluster.local", "kube-system", false },
		{ "right dots get stripped", "test.default.svc.cluster.local.", "default", true },
		{ "right dots get stripped wrong ns", "test.default.svc.cluster.local.", "kube-system", false },
		{ "dots get stripped", ".test.default.svc.cluster.local.", "default", true },
		{ "dots get stripped wrong ns", ".test.default.svc.cluster.local.", "kube-system", false },
		{ "cluster domain", "test.default.svc.cluster", "default", true },
		{ "cluster domain wrong ns", "test.default.svc.cluster", "kube-system", false },
		{ "service domain", "test.default.svc", "default", true },
		{ "service domain wrong ns", "test.default.svc", "kube-system", false },
		{ "two part domain", "test.default", "default", true },
		{ "two part domain different ns", "test.default", "kube-system", true },
		{ "one hostname", "test", "default", true },
		{ "no subject specified", "", "default", false },
		{ "three part not cluster", "test.default.com", "kube-system", true },
		{ "four part not cluster", "test.default.svc.com", "kube-system", true },
		{ "five part not cluster", "test.default.svc.cluster.com", "kube-system", true },
		{ "six part not cluster", "test.default.svc.cluster.local.com", "kube-system", true },
	}

	for _, testCase := range testCases {
		t.Run(testCase.description, func(t *testing.T) {
			if shouldMutate(&metav1.ObjectMeta{
				Annotations: map[string]string{
					admissionWebhookAnnotationKey: testCase.subject,
				},
			}, testCase.namespace) != testCase.expected {
				t.Errorf("shouldMutate did not return %t for %s", testCase.expected, testCase.description)
			}
		})
	}
}
