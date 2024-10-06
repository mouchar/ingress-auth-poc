update_settings(k8s_upsert_timeout_secs=120)
load('ext://helm_resource', 'helm_resource', 'helm_repo')
helm_repo('ingress-repo', 'https://kubernetes.github.io/ingress-nginx')
helm_resource(
    'ingress-nginx',
    chart='ingress-repo/ingress-nginx',
    namespace='ingress-nginx',
    flags=[
        '--create-namespace',
        '--wait',
        '--set', 'controller.hostPort.enabled=true',
        '--set', 'controller.service.type=NodePort',
        '--set', 'controller.watchIngressWithoutClass=true',
        '--set', 'controller.extraArgs.publish-status-address=localhost',
        '--set', 'controller.publishService.enabled=false',
    ],
    resource_deps=['ingress-repo'],
)

# load('ext://helm_remote', 'helm_remote')
# helm_remote(
#     'ingress-nginx',
#     repo_url='https://kubernetes.github.io/ingress-nginx',
#     namespace='ingress-nginx',
#     set=[
#         'controller.service.externalTrafficPolicy=Local'
#     ],
#     create_namespace=True
# )

docker_build(
    'auth-svc',
    context='apps/auth-svc',
    live_update=[
        sync('apps/auth-svc/src/auth_svc', '/app/auth_svc'),
        run(
            'uv pip install --no-cache --system -r requirements.lock',
            trigger='apps/auth_svc/requirements.lock'
        )
    ]
)

k8s_yaml(kustomize('manifests'))
