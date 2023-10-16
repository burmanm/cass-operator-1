package control

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/k8ssandra/cass-operator/pkg/httphelper"
	"github.com/k8ssandra/cass-operator/pkg/utils"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"

	cassapi "github.com/k8ssandra/cass-operator/apis/cassandra/v1beta1"
	api "github.com/k8ssandra/cass-operator/apis/control/v1alpha1"
)

// Cleanup functionality

func callCleanup(nodeMgmtClient httphelper.NodeMgmtClient, pod *corev1.Pod, taskConfig *TaskConfiguration) (string, error) {
	keyspaceName := taskConfig.Arguments.KeyspaceName
	tables := taskConfig.Arguments.Tables
	jobCount := -1
	if taskConfig.Arguments.JobsCount != nil {
		jobCount = *taskConfig.Arguments.JobsCount
	}
	return nodeMgmtClient.CallKeyspaceCleanup(pod, jobCount, keyspaceName, tables)
}

func callCleanupSync(nodeMgmtClient httphelper.NodeMgmtClient, pod *corev1.Pod, taskConfig *TaskConfiguration) error {
	keyspaceName := taskConfig.Arguments.KeyspaceName
	tables := taskConfig.Arguments.Tables
	jobCount := -1
	if taskConfig.Arguments.JobsCount != nil {
		jobCount = *taskConfig.Arguments.JobsCount
	}
	return nodeMgmtClient.CallKeyspaceCleanupEndpoint(pod, jobCount, keyspaceName, tables)
}

func cleanup(taskConfig *TaskConfiguration) {
	taskConfig.AsyncFeature = httphelper.AsyncSSTableTasks
	taskConfig.AsyncFunc = callCleanup
	taskConfig.SyncFunc = callCleanupSync
}

// Rebuild functionality

func callRebuild(nodeMgmtClient httphelper.NodeMgmtClient, pod *corev1.Pod, taskConfig *TaskConfiguration) (string, error) {
	return nodeMgmtClient.CallDatacenterRebuild(pod, taskConfig.Arguments.SourceDatacenter)
}

func rebuild(taskConfig *TaskConfiguration) {
	taskConfig.AsyncFeature = httphelper.Rebuild
	taskConfig.AsyncFunc = callRebuild
}

// Rolling restart functionality

func (r *CassandraTaskReconciler) restartSts(ctx context.Context, sts []appsv1.StatefulSet, taskConfig *TaskConfiguration) (ctrl.Result, error) {
	// Sort to ensure we don't process StatefulSets in wrong order and restart multiple racks at the same time
	sort.Slice(sts, func(i, j int) bool {
		return sts[i].Name < sts[j].Name
	})

	restartTime := taskConfig.TaskStartTime.Format(time.RFC3339)

	if taskConfig.Arguments.RackName != "" {
		singleSts := make([]appsv1.StatefulSet, 1)
		for _, st := range sts {
			if st.ObjectMeta.Labels[cassapi.RackLabel] == taskConfig.Arguments.RackName {
				singleSts[0] = st
				sts = singleSts
				break
			}
		}
	}
	restartedPods := 0
	for _, st := range sts {
		if st.Spec.Template.ObjectMeta.Annotations == nil {
			st.Spec.Template.ObjectMeta.Annotations = make(map[string]string)
		}
		if st.Spec.Template.ObjectMeta.Annotations[api.RestartedAtAnnotation] == restartTime {
			// This one has been called to restart already - is it ready?

			status := st.Status
			if status.CurrentRevision == status.UpdateRevision &&
				status.UpdatedReplicas == status.Replicas &&
				status.CurrentReplicas == status.Replicas &&
				status.ReadyReplicas == status.Replicas &&
				status.ObservedGeneration == st.GetObjectMeta().GetGeneration() {
				// This one has been updated, move on to the next one

				restartedPods += int(status.UpdatedReplicas)
				taskConfig.Completed = restartedPods
				continue
			}
			restartedPods += int(status.UpdatedReplicas)
			taskConfig.Completed = restartedPods
			// This is still restarting
			return ctrl.Result{RequeueAfter: JobRunningRequeue}, nil
		}
		st.Spec.Template.ObjectMeta.Annotations[api.RestartedAtAnnotation] = restartTime
		if err := r.Client.Update(ctx, &st); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{RequeueAfter: JobRunningRequeue}, nil
	}

	// We're done
	return ctrl.Result{}, nil
}

// UpgradeSSTables functionality

func callUpgradeSSTables(nodeMgmtClient httphelper.NodeMgmtClient, pod *corev1.Pod, taskConfig *TaskConfiguration) (string, error) {
	keyspaceName := taskConfig.Arguments.KeyspaceName
	tables := taskConfig.Arguments.Tables
	jobCount := -1
	if taskConfig.Arguments.JobsCount != nil {
		jobCount = *taskConfig.Arguments.JobsCount
	}

	return nodeMgmtClient.CallUpgradeSSTables(pod, jobCount, keyspaceName, tables)
}

func callUpgradeSSTablesSync(nodeMgmtClient httphelper.NodeMgmtClient, pod *corev1.Pod, taskConfig *TaskConfiguration) error {
	keyspaceName := taskConfig.Arguments.KeyspaceName
	tables := taskConfig.Arguments.Tables
	jobCount := -1
	if taskConfig.Arguments.JobsCount != nil {
		jobCount = *taskConfig.Arguments.JobsCount
	}
	return nodeMgmtClient.CallUpgradeSSTablesEndpoint(pod, jobCount, keyspaceName, tables)
}

func upgradesstables(taskConfig *TaskConfiguration) {
	taskConfig.AsyncFeature = httphelper.AsyncUpgradeSSTableTask
	taskConfig.AsyncFunc = callUpgradeSSTables
	taskConfig.SyncFunc = callUpgradeSSTablesSync
}

// Replace nodes functionality

// replacePod will drain the node, remove the PVCs and delete the pod. cass-operator will then call replace-node process when it starts Cassandra
func (r *CassandraTaskReconciler) replacePod(nodeMgmtClient httphelper.NodeMgmtClient, pod *corev1.Pod, taskConfig *TaskConfiguration) error {
	// We check the podStartTime to prevent replacing the pod multiple times since annotations are removed when we delete the pod
	podStartTime := pod.GetCreationTimestamp()
	uid := pod.UID
	podKey := types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}
	if podStartTime.Before(taskConfig.TaskStartTime) {
		if isCassandraUp(pod) {
			// Verify the cassandra pod is healthy before trying the drain
			if err := nodeMgmtClient.CallDrainEndpoint(pod); err != nil {
				return err
			}
		}

		// Get all the PVCs that the pod is using?
		pvcs, err := r.getPodPVCs(taskConfig.Context, taskConfig.Datacenter.Namespace, pod)
		if err != nil {
			return err
		}

		// Delete the PVCs .. without waiting (set status to terminating - finalizer will block)
		for _, pvc := range pvcs {
			if err := r.Client.Delete(taskConfig.Context, pvc); err != nil {
				return err
			}
		}

		// Finally, delete the pod
		if err := r.Client.Delete(taskConfig.Context, pod); err != nil {
			return err
		}
	}

	for i := 0; i < 10; i++ {
		time.Sleep(1 * time.Second)
		newPod := &corev1.Pod{}
		if err := r.Client.Get(taskConfig.Context, podKey, newPod); err != nil {
			continue
		}
		if uid != newPod.UID {
			break
		}
	}

	return nil
}

func (r *CassandraTaskReconciler) replaceValidator(taskConfig *TaskConfiguration) (bool, error) {
	// Check that arguments has replaceable pods and that those pods are actually existing pods
	if taskConfig.Arguments.PodName != "" {
		pods, err := r.getDatacenterPods(taskConfig.Context, taskConfig.Datacenter)
		if err != nil {
			return true, err
		}
		for _, pod := range pods {
			if pod.Name == taskConfig.Arguments.PodName {
				return true, nil
			}
		}
	}

	return false, fmt.Errorf("valid pod_name to replace is required")
}

func requiredPodFilter(pod *corev1.Pod, taskConfig *TaskConfiguration) bool {
	// If pod isn't in the to be replaced pods, return false
	podName := taskConfig.Arguments.PodName
	return pod.Name == podName
}

func genericPodFilter(pod *corev1.Pod, taskConfig *TaskConfiguration) bool {
	podName := taskConfig.Arguments.PodName
	if podName != "" {
		return pod.Name == podName
	}
	return true
}

// replacePreProcess adds enough information to CassandraDatacenter to ensure cass-operator knows this pod is being replaced
func (r *CassandraTaskReconciler) replacePreProcess(taskConfig *TaskConfiguration) error {
	dc := taskConfig.Datacenter
	podName := taskConfig.Arguments.PodName
	dc.Status.NodeReplacements = utils.AppendValuesToStringArrayIfNotPresent(
		dc.Status.NodeReplacements, podName)

	r.setDatacenterCondition(dc, cassapi.NewDatacenterCondition(cassapi.DatacenterReplacingNodes, corev1.ConditionTrue))

	return r.Client.Status().Update(taskConfig.Context, dc)
}

func (r *CassandraTaskReconciler) setDatacenterCondition(dc *cassapi.CassandraDatacenter, condition *cassapi.DatacenterCondition) {
	if dc.GetConditionStatus(condition.Type) != condition.Status {
		// We are changing the status, so record the transition time
		condition.LastTransitionTime = metav1.Now()
		dc.SetCondition(*condition)
	}
}

func (r *CassandraTaskReconciler) replace(taskConfig *TaskConfiguration) {
	taskConfig.SyncFunc = r.replacePod
	taskConfig.ValidateFunc = r.replaceValidator
	taskConfig.PodFilter = requiredPodFilter
	taskConfig.PreProcessFunc = r.replacePreProcess
}

// Move functionality

func callMove(nodeMgmtClient httphelper.NodeMgmtClient, pod *corev1.Pod, taskConfig *TaskConfiguration) (string, error) {
	newToken := taskConfig.Arguments.NewTokens[pod.Name]
	return nodeMgmtClient.CallMove(pod, newToken)
}

func moveFilter(pod *corev1.Pod, taskConfig *TaskConfiguration) bool {
	_, found := taskConfig.Arguments.NewTokens[pod.Name]
	return found
}

func (r *CassandraTaskReconciler) moveValidator(taskConfig *TaskConfiguration) (bool, error) {
	if len(taskConfig.Arguments.NewTokens) == 0 {
		return false, fmt.Errorf("missing required new_tokens argument")
	}
	pods, err := r.getDatacenterPods(taskConfig.Context, taskConfig.Datacenter)
	if err != nil {
		return true, err
	}
	for podName := range taskConfig.Arguments.NewTokens {
		found := false
		for _, pod := range pods {
			if pod.Name == podName {
				found = true
				break
			}
		}
		if !found {
			return false, fmt.Errorf("invalid new_tokens argument: pod doesn't exist: %s", podName)
		}
	}
	return true, nil
}

func (r *CassandraTaskReconciler) move(taskConfig *TaskConfiguration) {
	taskConfig.AsyncFeature = httphelper.Move
	taskConfig.AsyncFunc = callMove
	taskConfig.PodFilter = moveFilter
	taskConfig.ValidateFunc = r.moveValidator
}

// Flush functionality

func callFlushSync(nodeMgmtClient httphelper.NodeMgmtClient, pod *corev1.Pod, taskConfig *TaskConfiguration) error {
	keyspaceName := taskConfig.Arguments.KeyspaceName
	tables := taskConfig.Arguments.Tables
	return nodeMgmtClient.CallFlushEndpoint(pod, keyspaceName, tables)
}

func callFlushAsync(nodeMgmtClient httphelper.NodeMgmtClient, pod *corev1.Pod, taskConfig *TaskConfiguration) (string, error) {
	keyspaceName := taskConfig.Arguments.KeyspaceName
	tables := taskConfig.Arguments.Tables
	return nodeMgmtClient.CallFlush(pod, keyspaceName, tables)
}

func flush(taskConfig *TaskConfiguration) {
	taskConfig.AsyncFeature = httphelper.AsyncFlush
	taskConfig.PodFilter = genericPodFilter
	taskConfig.SyncFunc = callFlushSync
	taskConfig.AsyncFunc = callFlushAsync
}

// GarbageCollect functionality

func callGarbageCollectAsync(nodeMgmtClient httphelper.NodeMgmtClient, pod *corev1.Pod, taskConfig *TaskConfiguration) (string, error) {
	keyspaceName := taskConfig.Arguments.KeyspaceName
	tables := taskConfig.Arguments.Tables
	return nodeMgmtClient.CallGarbageCollect(pod, keyspaceName, tables)
}

func callGarbageCollectSync(nodeMgmtClient httphelper.NodeMgmtClient, pod *corev1.Pod, taskConfig *TaskConfiguration) error {
	keyspaceName := taskConfig.Arguments.KeyspaceName
	tables := taskConfig.Arguments.Tables
	return nodeMgmtClient.CallGarbageCollectEndpoint(pod, keyspaceName, tables)
}

func gc(taskConfig *TaskConfiguration) {
	taskConfig.AsyncFeature = httphelper.AsyncGarbageCollect
	taskConfig.PodFilter = genericPodFilter
	taskConfig.AsyncFunc = callGarbageCollectAsync
	taskConfig.SyncFunc = callGarbageCollectSync
}

// Scrub functionality

func createScrubRequest(taskConfig *TaskConfiguration) *httphelper.ScrubRequest {
	sr := &httphelper.ScrubRequest{
		DisableSnapshot: taskConfig.Arguments.NoSnapshot,
		SkipCorrupted:   taskConfig.Arguments.SkipCorrupted,
		CheckData:       !taskConfig.Arguments.NoValidate,
		Jobs:            -1,
		KeyspaceName:    taskConfig.Arguments.KeyspaceName,
		Tables:          taskConfig.Arguments.Tables,
	}

	if taskConfig.Arguments.JobsCount != nil {
		sr.Jobs = *taskConfig.Arguments.JobsCount
	}

	return sr
}

func scrubSync(nodeMgmtClient httphelper.NodeMgmtClient, pod *corev1.Pod, taskConfig *TaskConfiguration) error {
	return nodeMgmtClient.CallScrubEndpoint(pod, createScrubRequest(taskConfig))
}

func scrubAsync(nodeMgmtClient httphelper.NodeMgmtClient, pod *corev1.Pod, taskConfig *TaskConfiguration) (string, error) {
	return nodeMgmtClient.CallScrub(pod, createScrubRequest(taskConfig))
}

func scrub(taskConfig *TaskConfiguration) {
	taskConfig.AsyncFeature = httphelper.AsyncScrubTask
	taskConfig.PodFilter = genericPodFilter
	taskConfig.SyncFunc = scrubSync
	taskConfig.AsyncFunc = scrubAsync
}

// Compaction functionality

func createCompactRequest(taskConfig *TaskConfiguration) *httphelper.CompactRequest {
	return &httphelper.CompactRequest{
		KeyspaceName: taskConfig.Arguments.KeyspaceName,
		Tables:       taskConfig.Arguments.Tables,
		SplitOutput:  taskConfig.Arguments.SplitOutput,
		StartToken:   taskConfig.Arguments.StartToken,
		EndToken:     taskConfig.Arguments.EndToken,
	}
}

func compactSync(nodeMgmtClient httphelper.NodeMgmtClient, pod *corev1.Pod, taskConfig *TaskConfiguration) error {
	return nodeMgmtClient.CallCompactionEndpoint(pod, createCompactRequest(taskConfig))
}

func compactAsync(nodeMgmtClient httphelper.NodeMgmtClient, pod *corev1.Pod, taskConfig *TaskConfiguration) (string, error) {
	return nodeMgmtClient.CallCompaction(pod, createCompactRequest(taskConfig))
}

func compact(taskConfig *TaskConfiguration) {
	taskConfig.AsyncFeature = httphelper.AsyncCompactionTask
	taskConfig.PodFilter = genericPodFilter
	taskConfig.SyncFunc = compactSync
	taskConfig.AsyncFunc = compactAsync
}

// Common functions

func isCassandraUp(pod *corev1.Pod) bool {
	status := pod.Status
	statuses := status.ContainerStatuses
	ready := false
	for _, status := range statuses {
		if status.Name != "cassandra" {
			continue
		}
		ready = status.Ready
	}
	return ready
}

func (r *CassandraTaskReconciler) getPodPVCs(ctx context.Context, namespace string, pod *corev1.Pod) ([]*corev1.PersistentVolumeClaim, error) {
	pvcs := make([]*corev1.PersistentVolumeClaim, 0, len(pod.Spec.Volumes))
	for _, v := range pod.Spec.Volumes {
		if v.PersistentVolumeClaim == nil {
			continue
		}

		name := types.NamespacedName{
			Name:      v.PersistentVolumeClaim.ClaimName,
			Namespace: namespace,
		}

		podPvc := &corev1.PersistentVolumeClaim{}
		err := r.Client.Get(ctx, name, podPvc)
		if err != nil {
			return nil, err
		}

		pvcs = append(pvcs, podPvc)
	}
	return pvcs, nil
}
