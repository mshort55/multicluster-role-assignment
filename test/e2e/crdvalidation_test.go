/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/stolostron/multicluster-role-assignment/test/utils"
)

var _ = Describe("CRD Validation", Ordered, func() {
	BeforeEach(func() {
		cleanupCRDValidationTestMRA()
	})

	AfterEach(func() {
		cleanupCRDValidationTestMRA()
	})

	Context("spec.roleAssignments[].clusterRole validation", func() {
		DescribeTable("standard validation cases",
			func(roleName string, shouldSucceed bool) {
				yamlPath := createTestMRAYAML(roleName)
				defer os.Remove(yamlPath)

				if shouldSucceed {
					expectMRAApplyToSucceed(yamlPath)
				} else {
					expectMRAApplyToFail(yamlPath)
				}
			},
			// Valid cases
			Entry("should accept lowercase alphanumeric names", "view", true),
			Entry("should accept names with hyphens", "cluster-admin", true),
			Entry("should accept names with dots (DNS subdomain)", "example.com", true),
			Entry("should accept names with numbers", "role-123", true),
			Entry("should accept single character names", "a", true),
			Entry("should accept DNS subdomain with multiple segments", "subdomain.example.com", true),
			Entry("should accept numbers at start and end", "1role2", true),
			Entry("should accept mixed alphanumeric with dots and hyphens", "my-role.example-org.io", true),
			Entry("should accept names up to 253 characters", strings.Repeat("a", 253), true),

			// Invalid cases
			Entry("should reject names with uppercase characters", "MyRole", false),
			Entry("should reject names with underscores", "my_role", false),
			Entry("should reject names starting with hyphen", "-invalid", false),
			Entry("should reject names ending with hyphen", "invalid-", false),
			Entry("should reject names starting with dot", ".invalid", false),
			Entry("should reject names ending with dot", "invalid.", false),
			Entry("should reject names with special characters", "role@admin", false),
			Entry("should reject names with spaces", "my role", false),
			Entry("should reject empty names", "", false),
			Entry("should reject names with consecutive dots", "example..com", false),
			Entry("should reject names with hyphen after dot", "example.-com", false),
			Entry("should reject names with slashes", "example.com/my-role", false),
			Entry("should reject names exceeding 253 characters", strings.Repeat("a", 254), false),
		)
	})
})

// createTestMRAYAML creates a temporary MRA YAML file with a specific clusterRole value.
func createTestMRAYAML(clusterRoleName string) string {
	content := fmt.Sprintf(`apiVersion: rbac.open-cluster-management.io/v1beta1
kind: MulticlusterRoleAssignment
metadata:
  name: crd-validation-test
  namespace: %s
spec:
  subject:
    kind: User
    name: test-user
  roleAssignments:
    - name: test-assignment
      clusterRole: %s
      clusterSelection:
        type: placements
        placements:
          - name: test-placement
            namespace: %s
`, openClusterManagementGlobalSetNamespace, clusterRoleName, openClusterManagementGlobalSetNamespace)

	tmpFile, err := os.CreateTemp("", "mra-validation-*.yaml")
	Expect(err).NotTo(HaveOccurred())

	_, err = tmpFile.WriteString(content)
	Expect(err).NotTo(HaveOccurred())

	err = tmpFile.Close()
	Expect(err).NotTo(HaveOccurred())

	return tmpFile.Name()
}

// expectMRAApplyToFail applies MRA YAML via kubectl and expects it to fail with a validation error.
func expectMRAApplyToFail(yamlPath string) {
	cmd := exec.Command("kubectl", "apply", "-f", yamlPath)
	output, err := utils.Run(cmd)
	Expect(err).To(HaveOccurred())
	Expect(output).To(ContainSubstring("Invalid value"))
}

// expectMRAApplyToSucceed applies MRA YAML via kubectl and expects it to succeed.
func expectMRAApplyToSucceed(yamlPath string) {
	cmd := exec.Command("kubectl", "apply", "-f", yamlPath)
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred())
}

// cleanupCRDValidationTestMRA deletes the test MulticlusterRoleAssignment if it exists.
func cleanupCRDValidationTestMRA() {
	cmd := exec.Command("kubectl", "delete", "multiclusterroleassignment", "crd-validation-test", "-n",
		openClusterManagementGlobalSetNamespace, "--ignore-not-found=true")
	_, _ = utils.Run(cmd)
}
