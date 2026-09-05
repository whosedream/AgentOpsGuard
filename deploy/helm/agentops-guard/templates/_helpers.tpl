{{- define "agentops-guard.name" -}}
agentops-guard
{{- end -}}

{{- define "agentops-guard.labels" -}}
app.kubernetes.io/name: {{ include "agentops-guard.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "agentops-guard.podSecurityContext" -}}
securityContext:
  runAsNonRoot: true
  fsGroup: 10001
  fsGroupChangePolicy: OnRootMismatch
  seccompProfile:
    type: RuntimeDefault
{{- end -}}

{{- define "agentops-guard.containerSecurityContext" -}}
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
{{- end -}}

{{- define "agentops-guard.image" -}}
{{- $digest := default "" .Values.image.digest -}}
{{- if and .Values.supplyChain.requireImageDigests (not $digest) -}}
{{- fail "image.digest is required when supplyChain.requireImageDigests=true" -}}
{{- end -}}
{{- if and $digest (not (regexMatch "^sha256:[0-9a-f]{64}$" $digest)) -}}
{{- fail "image.digest must be sha256 followed by 64 lowercase hexadecimal characters" -}}
{{- end -}}
{{- if $digest -}}
{{ printf "%s@%s" .Values.image.repository $digest }}
{{- else -}}
{{ printf "%s:%s" .Values.image.repository .Values.image.tag }}
{{- end -}}
{{- end -}}

{{- define "agentops-guard.dashboardImage" -}}
{{- $digest := default "" .Values.dashboardImage.digest -}}
{{- if and .Values.supplyChain.requireImageDigests (not $digest) -}}
{{- fail "dashboardImage.digest is required when supplyChain.requireImageDigests=true" -}}
{{- end -}}
{{- if and $digest (not (regexMatch "^sha256:[0-9a-f]{64}$" $digest)) -}}
{{- fail "dashboardImage.digest must be sha256 followed by 64 lowercase hexadecimal characters" -}}
{{- end -}}
{{- if $digest -}}
{{ printf "%s@%s" .Values.dashboardImage.repository $digest }}
{{- else -}}
{{ printf "%s:%s" .Values.dashboardImage.repository .Values.dashboardImage.tag }}
{{- end -}}
{{- end -}}

{{- define "agentops-guard.opaImage" -}}
{{- $digest := default "" .Values.opa.image.digest -}}
{{- if and .Values.supplyChain.requireImageDigests .Values.opa.enabled (not $digest) -}}
{{- fail "opa.image.digest is required for production embedded OPA" -}}
{{- end -}}
{{- if and $digest (not (regexMatch "^sha256:[0-9a-f]{64}$" $digest)) -}}
{{- fail "opa.image.digest must be sha256 followed by 64 lowercase hexadecimal characters" -}}
{{- end -}}
{{- if $digest -}}
{{ printf "%s@%s" .Values.opa.image.repository $digest }}
{{- else -}}
{{ printf "%s:%s" .Values.opa.image.repository .Values.opa.image.tag }}
{{- end -}}
{{- end -}}

{{- define "agentops-guard.openbaoProxyImage" -}}
{{- $digest := default "" .Values.openbaoProxy.image.digest -}}
{{- if and .Values.supplyChain.requireImageDigests (not $digest) -}}
{{- fail "openbaoProxy.image.digest is required for production OpenBao Proxy" -}}
{{- end -}}
{{- if and $digest (not (regexMatch "^sha256:[0-9a-f]{64}$" $digest)) -}}
{{- fail "openbaoProxy.image.digest must be sha256 followed by 64 lowercase hexadecimal characters" -}}
{{- end -}}
{{- if $digest -}}
{{ printf "%s@%s" .Values.openbaoProxy.image.repository $digest }}
{{- else -}}
{{ printf "%s:%s" .Values.openbaoProxy.image.repository .Values.openbaoProxy.image.tag }}
{{- end -}}
{{- end -}}

{{- define "agentops-guard.openbaoRemoteUrl" -}}
{{- $url := required "credentialStore.openbaoUrl is required for OpenBao Proxy" .Values.credentialStore.openbaoUrl -}}
{{- if not (regexMatch "^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/?$" $url) -}}
{{- fail "credentialStore.openbaoUrl must be a credential-free HTTPS base URL" -}}
{{- end -}}
{{- $url -}}
{{- end -}}
