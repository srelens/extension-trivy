// Package workloads reads container identities through the app's three readers.
package workloads

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/srelens/srelens/sdk/go/sidecar"
)

type Reader interface {
	Read(context.Context, sidecar.CallContext, string) (json.RawMessage, error)
}
type Image struct {
	ClusterID       string `json:"clusterId"`
	Kind            string `json:"kind"`
	Namespace       string `json:"namespace"`
	Name            string `json:"name"`
	UID             string `json:"uid"`
	ResourceVersion string `json:"resourceVersion"`
	Container       string `json:"container"`
	ContainerType   string `json:"containerType"`
	Image           string `json:"image"`
	Scope           string `json:"scope"`
}

func ListImages(ctx context.Context, r Reader, cluster string, namespace *string) ([]Image, error) {
	cc, err := sidecar.NewCallContext(cluster, namespace)
	if err != nil {
		return nil, err
	}
	out := []Image{}
	for _, binding := range []string{"deployment-images", "statefulset-images", "daemonset-images"} {
		data, err := r.Read(ctx, cc, binding)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", binding, err)
		}
		var list struct {
			Items []struct {
				Kind, Namespace, Name, UID, ResourceVersion string
				Containers                                  []struct{ Name, Type, Image string }
			}
			Truncated bool
		}
		if len(data) > 4*1024*1024 || json.Unmarshal(data, &list) != nil || list.Items == nil || list.Truncated {
			return nil, fmt.Errorf("%s returned an invalid or incomplete workload list", binding)
		}
		for _, item := range list.Items {
			if item.Name == "" || item.UID == "" || item.ResourceVersion == "" || item.Containers == nil {
				return nil, fmt.Errorf("%s returned incomplete workload identity", binding)
			}
			for _, container := range item.Containers {
				scope := "OS and supported language packages"
				if container.Image == "" {
					scope = "Image reference missing; cannot scan"
				}
				out = append(out, Image{cluster, item.Kind, item.Namespace, item.Name, item.UID, item.ResourceVersion, container.Name, container.Type, container.Image, scope})
				if len(out) > 1000 {
					return nil, fmt.Errorf("more than 1,000 workload containers; narrow the namespace")
				}
			}
		}
	}
	return out, nil
}
