{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "zservice.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "zservice.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "zservice.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "zservice.labels" -}}
helm.sh/chart: {{ include "zservice.chart" . }}
{{ include "zservice.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "zservice.selectorLabels" -}}
app.kubernetes.io/name: {{ include "zservice.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "zservice.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "zservice.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create args that vary based on .Values.personality
*/}}
{{- define "zservice.args" -}}
{{- $args := list "listen" "-l=:9867" }}
{{- $args = append $args (print "-personality=" .Values.personality) }}
{{- if ne .Values.personality "recruiter" }}
{{- $args = append $args (print "-worker.recruiter=" .Values.recruiterAddr) }}
{{- end }}
{{- if eq .Values.personality "root" }}
{{- $args = append $args (print "-data=" .Values.datauri) }}
{{- $args = append $args (print "-db.kind=postgres") }}
{{- $args = append $args (print "-db.postgres.addr=" .Values.postgres.addr) }}
{{- $args = append $args (print "-db.postgres.database=" .Values.postgres.database) }}
{{- $args = append $args (print "-db.postgres.user=" .Values.postgres.username) }}
{{- $args = append $args (print "-db.postgres.passwordFile=/creds/postgres/password") }}
{{- $args = append $args (print "-immcache.kind=redis") }}
{{- $args = append $args (print "-redis.enabled") }}
{{- $args = append $args (print "-redis.addr=" .Values.redis.addr) }}
{{- $args = append $args (print "-redis.passwordFile=/creds/redis/password") }}
{{- else if eq .Values.personality "worker" }}
{{- $args = append $args "-worker.host=$(STATUS_POD_IP)" }}
{{- $args = append $args "-worker.node=$(SPEC_NODE_NAME)" }}
{{- end }}
{{- range $args }}
{{ print "- " (. | quote) }}
{{- end }}
{{- end }}
