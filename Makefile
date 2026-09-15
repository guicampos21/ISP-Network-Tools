PYTHON ?= python3

.PHONY: check test compile compose-config secret-check

check: compile secret-check

compile:
	$(PYTHON) -m compileall -q apps/admin-center/geofeed_admin apps/isp-network-health/src apps/isp-network-health/isp_health

test:
	PYTHONPATH=apps/admin-center:packages $(PYTHON) -m pytest -q apps/admin-center/tests
	PYTHONPATH=apps/isp-network-health/src $(PYTHON) -m unittest discover -s apps/isp-network-health/tests -v

compose-config:
	test -f .env || cp .env.example .env
	SECRETS_DIR=$${SECRETS_DIR:-.local/secrets} ./scripts/bootstrap-secrets.sh
	docker compose config --quiet

secret-check:
	./scripts/secret-check.sh
