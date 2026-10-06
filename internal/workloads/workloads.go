// Package workloads reads container identities through the app's three readers.
package workloads

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/srelens/srelens/sdk/go/sidecar"
)

type Reader interface {
	ReadPage(context.Context, sidecar.CallContext, string, string) (json.RawMessage, error)
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

type ImagePage struct {
	Items      []Image `json:"items"`
	NextCursor string  `json:"nextCursor"`
}
type imageCursor struct {
	Cluster   string  `json:"cluster"`
	Namespace *string `json:"namespace"`
	Binding   int     `json:"binding"`
	Reader    string  `json:"reader"`
}

func ListImagePage(ctx context.Context, r Reader, cluster string, namespace *string, cursor string) (ImagePage, error) {
	page := ImagePage{Items: []Image{}}
	cc, err := sidecar.NewCallContext(cluster, namespace)
	if err != nil {
		return page, err
	}
	c := imageCursor{Cluster: cluster, Namespace: namespace}
	if cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(cursor)
		if len(cursor) > 8192 || err != nil || json.Unmarshal(raw, &c) != nil || c.Cluster != cluster || c.Binding < 0 || c.Binding > 2 || (c.Namespace == nil) != (namespace == nil) || (namespace != nil && *c.Namespace != *namespace) {
			return page, sidecar.InvalidParams("This image cursor belongs to another cluster or namespace, or is invalid; refresh Images")
		}
	}
	bindings := []string{"deployment-images", "statefulset-images", "daemonset-images"}
	for c.Binding < len(bindings) {
		binding := bindings[c.Binding]
		data, err := r.ReadPage(ctx, cc, binding, c.Reader)
		if err != nil {
			return page, fmt.Errorf("reading %s: %w", binding, err)
		}
		var list struct {
			Items []struct {
				Kind, Namespace, Name, UID, ResourceVersion string
				Containers                                  []struct{ Name, Type, Image string }
			}
			NextCursor string
			Truncated  bool
		}
		if len(data) > 4*1024*1024 || json.Unmarshal(data, &list) != nil || list.Items == nil || list.Truncated || len(list.NextCursor) > 8192 || (list.NextCursor != "" && list.NextCursor == c.Reader) {
			return page, fmt.Errorf("%s returned an invalid or incomplete workload page", binding)
		}
		for _, item := range list.Items {
			if item.Name == "" || item.UID == "" || item.ResourceVersion == "" || item.Containers == nil || (namespace != nil && item.Namespace != *namespace) {
				return page, fmt.Errorf("%s returned incomplete or out-of-scope workload identity", binding)
			}
			for _, container := range item.Containers {
				scope := "OS and supported language packages"
				if container.Image == "" {
					scope = "Image reference missing; cannot scan"
				}
				page.Items = append(page.Items, Image{cluster, item.Kind, item.Namespace, item.Name, item.UID, item.ResourceVersion, container.Name, container.Type, container.Image, scope})
				if len(page.Items) > 1000 {
					return ImagePage{}, fmt.Errorf("this workload page exceeds 1,000 containers; narrow the namespace")
				}
			}
		}
		c.Reader = list.NextCursor
		if c.Reader == "" {
			c.Binding++
		}
		if len(page.Items) > 0 || c.Reader != "" {
			break
		}
	}
	if c.Binding < len(bindings) {
		raw, _ := json.Marshal(c)
		page.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
		if len(page.NextCursor) > 8192 {
			return ImagePage{}, fmt.Errorf("the image continuation exceeds its message limit")
		}
	}
	return page, nil
}
