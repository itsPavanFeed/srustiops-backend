{{- define "tenant.name" -}}{{ .Release.Name }}-tenant{{- end -}}
{{- define "tenant.labels" -}}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
srustiops/tenant: {{ .Values.tenant }}
{{- end -}}
{{- define "srustiops.securityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
runAsUser: 65532
capabilities: { drop: [ALL] }
seccompProfile: { type: RuntimeDefault }
{{- end -}}
{{/* Egress every pod may use when egress is locked down: DNS, then the listed destinations. */}}
{{- define "srustiops.egress" -}}
- to:
    - namespaceSelector: {}
      podSelector: { matchLabels: { k8s-app: kube-dns } }
  ports: [{ port: 53, protocol: UDP }, { port: 53, protocol: TCP }]
{{- with .Values.networkPolicy.egress.to }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/* Secrets made by the bootstrap Job when install.token is set, else the configured ones. */}}
{{- define "srustiops.installed" -}}{{ if or .Values.install.token .Values.install.existingSecret }}true{{ end }}{{- end -}}
{{- define "srustiops.tlsSecret" -}}{{ if include "srustiops.installed" . }}{{ .Release.Name }}-tls{{ else }}{{ .Values.tls.secretName }}{{ end }}{{- end -}}
{{- define "srustiops.centralCASecret" -}}{{ if include "srustiops.installed" . }}{{ .Release.Name }}-central-ca{{ else }}{{ .Values.central.clientCASecret }}{{ end }}{{- end -}}
{{- define "srustiops.enrollSecret" -}}{{ if include "srustiops.installed" . }}{{ .Release.Name }}-link-enroll{{ else }}{{ .Values.link.enrollTokenSecret }}{{ end }}{{- end -}}
{{- define "srustiops.linkMode" -}}{{ if eq .Values.connectivity "tunnel" }}tunnel{{ else }}control{{ end }}{{- end -}}
