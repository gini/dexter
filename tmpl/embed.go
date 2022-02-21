package tmpl

import _ "embed"

//go:embed kube-config.yaml
var KubeConfigTemplate string
