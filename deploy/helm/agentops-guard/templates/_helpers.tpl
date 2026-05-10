{{- define "agentops-guard.name" -}}
agentops-guard
{{- end -}}

{{- define "agentops-guard.labels" -}}
app.kubernetes.io/name: {{ include "agentops-guard.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
