"""
Names of widely used software, tools, products and cloud terms that spaCy's name
recognizer reads as a PERSON ("Jenkins", "Grafana Tempo", "kube"). A PERSON span
that is exactly one of these (or built only from these plus the generic product
words below) is not reported. See pii_guard.filters for how it is applied.

How to extend: add a lowercase entry to IGNORE_NAMES (one word, or a short
phrase with single spaces) and keep it to names of things, not of people. An
entry here means a real person with exactly that name, mentioned alone and not
after a title, is NOT flagged; that is the cost, so leave out words that are
mostly given names or surnames (hugo, linus, chandler, jordan, ...). Without
editing code, an operator adds names with PII_IGNORE_NAMES (comma-separated).
"""

# Orchestration, containers, cloud
_PLATFORM = """
kubernetes kube k8s k3s k3d kubectl kubelet kubeadm kustomize minikube rancher openshift
docker podman containerd cri-o buildkit buildah skaffold tilt helm argo argocd flux fluxcd
istio linkerd envoy nomad vault terraform terragrunt pulumi ansible packer vagrant puppet
saltstack crossplane karpenter cilium calico flannel traefik nginx haproxy caddy
ingress coredns etcd ceph longhorn velero quay gitea gitlab github bitbucket
jenkins circleci travis tekton spinnaker teamcity bamboo buildkite
aws gcp azure arn iam ecr eks ecs ec2 s3 rds sqs sns lambda fargate cloudformation cloudwatch
cloudfront route53 gke aks oci lightsail openstack vmware esxi proxmox
"""

# Observability, security
_OBSERVABILITY = """
grafana tempo loki mimir prometheus alertmanager thanos cortex jaeger zipkin opentelemetry otel
datadog newrelic splunk dynatrace sentry nagios zabbix icinga kibana logstash fluentd fluentbit
promtail victoriametrics statsd telegraf influxdb graphite opensearch
keycloak okta auth0 oauth openid oidc saml ldap kerberos sops trivy falco snyk sonarqube
gitleaks presidio spacy
"""

# Data, streaming, storage
_DATA = """
kafka zookeeper rabbitmq activemq pulsar nats redpanda kinesis flink spark hadoop hive hdfs yarn
airflow dagster prefect luigi dbt trino presto druid pinot clickhouse snowflake bigquery redshift
databricks delta iceberg hudi parquet avro protobuf thrift grpc graphql
postgres postgresql mysql mariadb sqlite mongodb cassandra scylla couchdb couchbase dynamodb
cockroachdb timescaledb neo4j redis memcached elasticsearch elastic solr lucene minio
supabase firebase pgbouncer patroni cnpg
"""

# Languages, frameworks, libraries, ML
_DEV = """
python java javascript typescript golang rust perl php kotlin scala elixir erlang
haskell clojure lua
node nodejs deno npm yarn pnpm webpack vite rollup babel eslint prettier jest mocha pytest
flask django fastapi uvicorn gunicorn celery pydantic sqlalchemy alembic pandas numpy scipy
matplotlib jupyter jupyterlab jupyterhub ipython notebook rails sinatra laravel symfony
hibernate maven gradle quarkus micronaut react angular vue svelte nextjs nuxt
tensorflow pytorch keras sklearn xgboost lightgbm huggingface transformers langchain llamaindex
ollama onnx cuda triton mlflow kubeflow dask polars
git svn mercurial bazel cmake
ubuntu debian centos fedora alpine rhel suse archlinux macos windows linux
vscode intellij pycharm vim emacs neovim
slack jira confluence notion trello asana zendesk pagerduty opsgenie
"""

# Words that follow or precede a tool name in a product name ("Jupyter Lab",
# "Kafka Streams", "Grafana Tempo"). Never enough alone: a span needs at least
# one IGNORE_NAMES word as well.
PRODUCT_WORDS = frozenset(
    [
        "lab",
        "hub",
        "notebook",
        "notebooks",
        "streams",
        "stream",
        "connect",
        "server",
        "client",
        "cli",
        "cloud",
        "enterprise",
        "operator",
        "controller",
        "gateway",
        "proxy",
        "mesh",
        "engine",
        "core",
        "studio",
        "desktop",
        "agent",
        "agents",
        "runner",
        "runners",
        "cluster",
        "dashboard",
        "dashboards",
        "api",
        "sdk",
        "ui",
        "web",
        "worker",
        "workers",
        "scheduler",
        "registry",
        "manager",
        "console",
        "compose",
        "swarm",
        "tower",
    ]
)

IGNORE_NAMES = frozenset((_PLATFORM + _OBSERVABILITY + _DATA + _DEV).split())
