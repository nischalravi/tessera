{{- define "tessera.name" -}}{{ default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "tessera.fullname" -}}
{{- if .Values.fullnameOverride -}}{{ .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else -}}{{- $n := default .Chart.Name .Values.nameOverride -}}
{{- if contains $n .Release.Name -}}{{ .Release.Name | trunc 63 | trimSuffix "-" }}{{- else -}}{{ printf "%s-%s" .Release.Name $n | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- end -}}
{{- end -}}
{{- define "tessera.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "tessera.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.api.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "tessera.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tessera.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "tessera.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}{{ default (include "tessera.fullname" .) .Values.serviceAccount.name }}{{- else -}}{{ default "default" .Values.serviceAccount.name }}{{- end -}}
{{- end -}}
{{- /* Name of the Secret that holds TESSERA_DB, TESSERA_DB_APP, TESSERA_KEK (and any other secret env). */ -}}
{{- define "tessera.secretName" -}}
{{- if .Values.csi.enabled -}}{{ default (printf "%s-env" (include "tessera.fullname" .)) .Values.csi.syncedSecretName }}
{{- else -}}{{ required "secrets.existingSecret is required (a Secret with keys TESSERA_DB, TESSERA_DB_APP, TESSERA_KEK), or enable csi" .Values.secrets.existingSecret }}{{- end -}}
{{- end -}}
{{- define "tessera.image" -}}{{- if .digest -}}{{ printf "%s:%s@%s" .repository (.tag | default "latest") .digest }}{{- else -}}{{ printf "%s:%s" .repository (.tag | default "latest") }}{{- end -}}{{- end -}}
{{- /* Pod security context shared by every pod of the chart. OpenShift assigns uid and fsGroup itself. */ -}}
{{- define "tessera.podSecurityContext" -}}
runAsNonRoot: true
seccompProfile:
  type: RuntimeDefault
{{- if not .Values.openshift.enabled }}
runAsUser: {{ .Values.securityContext.runAsUser }}
runAsGroup: {{ .Values.securityContext.runAsUser }}
fsGroup: {{ .Values.securityContext.runAsUser }}
{{- end }}
{{- end -}}
{{- define "tessera.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
capabilities:
  drop: ["ALL"]
seccompProfile:
  type: RuntimeDefault
{{- end -}}
{{- define "tessera.trustedProxies" -}}
{{- join "," (required "config.trustedProxies must list the CIDRs of the hops in front of the pod (ingress controller / load balancer), none broader than /8" .Values.config.trustedProxies) -}}
{{- end -}}
