// Copyright DataStax, Inc.
// Please see the included license file for details.

package rolling_restart

import (
	"fmt"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"

	"github.com/k8ssandra/cass-operator/tests/kustomize"
	ginkgo_util "github.com/k8ssandra/cass-operator/tests/util/ginkgo"
	"github.com/k8ssandra/cass-operator/tests/util/kubectl"
)

var (
	testName   = "Rolling Restart"
	namespace  = "test-rolling-restart"
	dcName     = "dc2"
	dcYaml     = "../testdata/default-single-rack-2-node-dc.yaml"
	dcResource = fmt.Sprintf("CassandraDatacenter/%s", dcName)
	ns         = ginkgo_util.NewWrapper(testName, namespace)
)

func TestLifecycle(t *testing.T) {
	AfterSuite(func() {
		logPath := fmt.Sprintf("%s/aftersuite", ns.LogDir)
		err := kubectl.DumpAllLogs(logPath).ExecV()
		if err != nil {
			t.Logf("Failed to dump all the logs: %v", err)
		}

		fmt.Printf("\n\tPost-run logs dumped at: %s\n\n", logPath)
		ns.Terminate()
		err = kustomize.Undeploy(namespace)
		if err != nil {
			t.Logf("Failed to undeploy cass-operator: %v", err)
		}
	})

	RegisterFailHandler(Fail)
	RunSpecs(t, testName)
}

var _ = Describe(testName, func() {
	Context("when in a new cluster", func() {
		Specify("the operator can perform a rolling restart", func() {
			By("deploy cass-operator with kustomize")
			err := kustomize.Deploy(namespace)
			Expect(err).ToNot(HaveOccurred())

			ns.WaitForOperatorReady()

			step := "creating a datacenter resource with 1 rack/2 node"
			k := kubectl.ApplyFiles(dcYaml)
			ns.ExecAndLog(step, k)

			ns.WaitForDatacenterReady(dcName)

			step = "trigger restart"
			json := `{"spec": {"rollingRestartRequested": true}}`
			k = kubectl.PatchMerge(dcResource, json)
			ns.ExecAndLog(step, k)

			// Ensure we actually set the condition
			ns.WaitForDatacenterCondition(dcName, "RollingRestart", string(corev1.ConditionTrue))

			// Ensure we actually unset the condition
			ns.WaitForDatacenterCondition(dcName, "RollingRestart", string(corev1.ConditionFalse))

			// Once the RollingRestart condition becomes true, all the pods in the cluster
			// _should_ be ready
			step = "get ready pods"
			json = "jsonpath={.items[*].status.containerStatuses[0].ready}"
			k = kubectl.Get("pods").
				WithLabel(fmt.Sprintf("cassandra.datastax.com/datacenter=%s", dcName)).
				WithFlag("field-selector", "status.phase=Running").
				FormatOutput(json)

			Expect(ns.OutputAndLog(step, k)).To(Equal("true true"))

			ns.WaitForDatacenterReady(dcName)
		})
	})
})
