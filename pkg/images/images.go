// Copyright DataStax, Inc.
// Please see the included license file for details.

package images

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	configv1beta1 "github.com/k8ssandra/cass-operator/apis/config/v1beta1"
)

var (
	imageConfig *configv1beta1.ImageConfig
	scheme      = runtime.NewScheme()
)

const (
	ValidDseVersionRegexp   = "6\\.8\\.\\d+"
	ValidOssVersionRegexp   = "(3\\.11\\.\\d+)|(4\\.0\\.\\d+)"
	CassandraImageComponent = "k8ssandra/cass-management-api"
	DSEImageComponent       = "datastax/dse-server"
)

func init() {
	utilruntime.Must(configv1beta1.AddToScheme(scheme))
}

func ParseImageConfig(imageConfigFile string) error {
	// Mostly from controller-runtime, modified here to avoid needing ControllerManagerConfigurationSpec in the ImageConfig
	content, err := ioutil.ReadFile(imageConfigFile)
	if err != nil {
		return fmt.Errorf("could not read file at %s", imageConfigFile)
	}

	codecs := serializer.NewCodecFactory(scheme)

	// Regardless of if the bytes are of any external version,
	// it will be read successfully and converted into the internal version
	emptyImageConfig := configv1beta1.ImageConfig{}
	if err = runtime.DecodeInto(codecs.UniversalDecoder(), content, &emptyImageConfig); err != nil {
		return fmt.Errorf("could not decode file into runtime.Object")
	}

	imageConfig = &emptyImageConfig
	return nil
}

var log = logf.Log.WithName("images")

func IsDseVersionSupported(version string) bool {
	validVersions := regexp.MustCompile(ValidDseVersionRegexp)
	return validVersions.MatchString(version)
}

func IsOssVersionSupported(version string) bool {
	validVersions := regexp.MustCompile(ValidOssVersionRegexp)
	return validVersions.MatchString(version)
}

func stripRegistry(image string) string {
	comps := strings.Split(image, "/")

	if len(comps) > 1 && strings.Contains(comps[0], ".") || strings.Contains(comps[0], ":") {
		return strings.Join(comps[1:], "/")
	} else {
		return image
	}
}

func applyDefaultRegistryOverride(image string) string {
	customRegistry := GetImageConfig().ImageRegistry
	customRegistry = strings.TrimSuffix(customRegistry, "/")

	if customRegistry == "" {
		return image
	} else {
		imageNoRegistry := stripRegistry(image)
		return fmt.Sprintf("%s/%s", customRegistry, imageNoRegistry)
	}
}

func ApplyRegistry(image string) string {
	return applyDefaultRegistryOverride(image)
}

func GetImageConfig() *configv1beta1.ImageConfig {
	// For now, this is static configuration (updated only on start of the pod), even if the actual ConfigMap underneath is updated.
	return imageConfig
}

func getCassandraContainerImageOverride(serverType, version string) (bool, string) {
	// If there's a mapped volume with overrides in the ConfigMap, use these. Otherwise only calculate
	images := GetImageConfig().Images
	if images != nil {
		if serverType == "dse" {
			if value, found := images.DSEVersions[version]; found {
				return true, value
			}
		}
		if serverType == "cassandra" {
			if value, found := images.CassandraVersions[version]; found {
				return true, value
			}
		}
	}
	return false, ""
}

func GetCassandraImage(serverType, version string) (string, error) {
	if found, image := getCassandraContainerImageOverride(serverType, version); found {
		return ApplyRegistry(image), nil
	}

	imagePrefix := CassandraImageComponent

	if serverType == "dse" {
		if !IsDseVersionSupported(version) {
			return "", fmt.Errorf("server 'dse' and version '%s' do not work together", version)
		}
		imagePrefix = DSEImageComponent
	} else {
		if !IsOssVersionSupported(version) {
			return "", fmt.Errorf("server 'cassandra' and version '%s' do not work together", version)
		}
	}

	return ApplyRegistry(fmt.Sprintf("%s:%s", imagePrefix, version)), nil
}

func GetConfigBuilderImage() string {
	return ApplyRegistry(GetImageConfig().Images.ConfigBuilder)
}

func GetSystemLoggerImage() string {
	return ApplyRegistry(GetImageConfig().Images.SystemLogger)
}

func AddDefaultRegistryImagePullSecrets(podSpec *corev1.PodSpec) bool {
	secretName := GetImageConfig().ImagePullSecret.Name
	if secretName != "" {
		podSpec.ImagePullSecrets = append(
			podSpec.ImagePullSecrets,
			corev1.LocalObjectReference{Name: secretName})
		return true
	}
	return false
}
