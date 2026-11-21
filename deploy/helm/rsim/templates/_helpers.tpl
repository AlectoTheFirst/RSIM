{{- define "rsim.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "rsim.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else if contains (include "rsim.name" .) .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "rsim.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "rsim.selectorLabels" -}}
app.kubernetes.io/name: {{ include "rsim.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "rsim.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{ include "rsim.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* An image reference: repository with the digest, else with the tag, else with the app version. */}}
{{- define "rsim.image" -}}
{{- if .digest -}}
{{ .repository }}@{{ .digest }}
{{- else -}}
{{ .repository }}:{{ default .appVersion .tag }}
{{- end -}}
{{- end -}}

{{- define "rsim.secretName" -}}
{{- default (printf "%s-db" (include "rsim.fullname" .)) .Values.secrets.existingSecret -}}
{{- end -}}

{{- define "rsim.postgresHost" -}}
{{ include "rsim.fullname" . }}-postgres
{{- end -}}

{{/* The environment of the inventory database URL. */}}
{{- define "rsim.databaseEnv" -}}
- name: RSIM_DB_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "rsim.secretName" . }}
      key: postgres-password
- name: RSIM_INVENTORY_URL
  value: postgres://{{ .Values.postgres.username }}:$(RSIM_DB_PASSWORD)@{{ include "rsim.postgresHost" . }}:5432/{{ .Values.postgres.database }}
{{- end -}}

{{/* The origins of the server: the ingress host and api.publicOrigins. */}}
{{- define "rsim.publicOrigins" -}}
{{- $o := list -}}
{{- if .Values.ingress.enabled -}}
{{- $o = append $o (printf "%s://%s" (ternary "https" "http" .Values.ingress.tls.enabled) .Values.ingress.host) -}}
{{- end -}}
{{- range .Values.api.publicOrigins -}}
{{- $o = append $o . -}}
{{- end -}}
{{- toJson $o -}}
{{- end -}}

{{- define "rsim.validate" -}}
{{- if and .Values.ingress.enabled (not .Values.ingress.host) -}}
{{- fail "ingress.enabled needs ingress.host" -}}
{{- end -}}
{{- if and .Values.ingress.enabled .Values.ingress.tls.enabled (not .Values.ingress.tls.secretName) -}}
{{- fail "ingress.tls.enabled needs ingress.tls.secretName" -}}
{{- end -}}
{{- range (include "rsim.publicOrigins" . | fromJsonArray) -}}
{{- if and (hasPrefix "https://" .) (not $.Values.api.trustedProxies) -}}
{{- fail (printf "the https origin %s needs api.trustedProxies: the address of the proxy that ends TLS" .) -}}
{{- end -}}
{{- end -}}
{{- if and (not .Values.secrets.existingSecret) (not .Values.secrets.postgresPassword) -}}
{{- fail "set secrets.existingSecret, or secrets.postgresPassword" -}}
{{- end -}}
{{- if and .Values.collector.enabled (not .Values.collector.envSecret) -}}
{{- fail "collector.enabled needs collector.envSecret" -}}
{{- end -}}
{{- end -}}
