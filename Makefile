REPORT_FILE := tests/TEST_REPORT.txt
MUTATION_IMAGE := codex-auth-mutation
MUTATION_DOCKERFILE := tests/Dockerfile.mutation
SONAR_IMAGE := sonarsource/sonar-scanner-cli
SONAR_PROJECT := codex-auth
SONAR_TOKEN := sqp_a6787808e65d5c4ad38c62f60858dae3c19f3f15

.PHONY: report clean-report make-report sonar-up sonar-down sonar-run lint unit-test benchmark-test mutation-test integration-test fuzz-test

unit-test:
	go test -v -tags=!integration,!fuzz ./...

benchmark-test:
	RUN_BENCHMARKS=1 go test -bench=. -benchmem ./adapters/hasher/...

mutation-test:
	docker build -q -f $(MUTATION_DOCKERFILE) -t $(MUTATION_IMAGE) . > /dev/null
	docker run --rm $(MUTATION_IMAGE)

integration-test:
	go test -tags=integration ./tests/bdd -v

fuzz-test:
	go test -tags=fuzz ./tests/fuzz -fuzz=FuzzLogin -fuzztime=120s

lint:
	golangci-lint run ./...

report: clean-report make-report

clean-report:
	@rm -f $(REPORT_FILE) || true
	@touch $(REPORT_FILE)

make-report:
	@echo "==================================================" | tee -a $(REPORT_FILE)
	@echo "         CODEX-AUTH AUTOMATED TEST REPORT         " | tee -a $(REPORT_FILE)
	@echo "==================================================" | tee -a $(REPORT_FILE)
	@date >> $(REPORT_FILE)
	@echo "" >> $(REPORT_FILE)

	@# ------------------------------------------------------------------
	@# UNIT TESTS
	@# ------------------------------------------------------------------
	@echo "UNIT TESTING & COVERAGE" | tee -a $(REPORT_FILE)
	@echo "Description:" >> $(REPORT_FILE)
	@echo "  - Domain Logic: Black Box Testing (equivalence partitioning, boundary value analysis)" >> $(REPORT_FILE)
	@echo "  - Service Logic: White Box Testing (branch testing with mocks)" >> $(REPORT_FILE)
	@echo "  - Adapters: White Box Testing (statement testing)" >> $(REPORT_FILE)
	@echo "--------------------------------------------------" >> $(REPORT_FILE)
	@make unit-test >> $(REPORT_FILE)
	@echo "" >> $(REPORT_FILE)

	@# ------------------------------------------------------------------
	@# BENCHMARK TESTS
	@# ------------------------------------------------------------------
	@echo "BENCHMARK TESTING" | tee -a $(REPORT_FILE)
	@echo "Description:" >> $(REPORT_FILE)
	@echo "  - Comparing algorithms: Bcrypt (Secure) vs SHA256 (Fast)" >> $(REPORT_FILE)
	@echo "  - Methodology: Processing dataset of varying lengths" >> $(REPORT_FILE)
	@echo "  - Loading test scenarios from JSON file" >> $(REPORT_FILE)
	@echo "  - Testing Assumptions (Skipping if file missing)" >> $(REPORT_FILE)
	@echo "--------------------------------------------------" >> $(REPORT_FILE)
	@make benchmark-test >> $(REPORT_FILE)
	@echo "" >> $(REPORT_FILE)

	@# ------------------------------------------------------------------
	@# MUTATION TESTING
	@# ------------------------------------------------------------------
	@echo "MUTATION TESTING" | tee -a $(REPORT_FILE)
	@echo "Description:" >> $(REPORT_FILE)
	@echo "  - Tool: gremlins" >> $(REPORT_FILE)
	@echo "  - Scope: Core Domain & Service logic" >> $(REPORT_FILE)
	@echo "  - Detailed output will be included in this report" >> $(REPORT_FILE)
	@echo "--------------------------------------------------" >> $(REPORT_FILE)
	@echo "Building Mutation Docker Image..."
	@docker build -q -f $(MUTATION_DOCKERFILE) -t $(MUTATION_IMAGE) . > /dev/null
	@echo "Running Mutation Tests (This may take a while)..."
	@make mutation-test >> $(REPORT_FILE)
	@echo "" >> $(REPORT_FILE)

	@# ------------------------------------------------------------------
	@# INTEGRATION TESTS
	@# ------------------------------------------------------------------
	@echo "INTEGRATION TESTING" | tee -a $(REPORT_FILE)
	@echo "Description:" >> $(REPORT_FILE)
	@echo "  - Tool: cucumber/godog" >> $(REPORT_FILE)
	@echo "  - BDD Testing" >> $(REPORT_FILE)
	@echo "--------------------------------------------------" >> $(REPORT_FILE)
	@make integration-test >> $(REPORT_FILE)
	@echo "" >> $(REPORT_FILE)	

	@# ------------------------------------------------------------------
	@# LINTING
	@# ------------------------------------------------------------------
	@echo "LINTING" | tee -a $(REPORT_FILE)
	@echo "Description:" >> $(REPORT_FILE)
	@echo "  - Tool: golangci-lint" >> $(REPORT_FILE)
	@echo "  - Scope: All code" >> $(REPORT_FILE)
	@echo "--------------------------------------------------" >> $(REPORT_FILE)
	@make lint >> $(REPORT_FILE)
	@echo "" >> $(REPORT_FILE)

sonar-up:
	docker compose -f tests/docker-compose.sonarqube.yml up -d

sonar-down:
	docker compose -f tests/docker-compose.sonarqube.yml down

sonar-run:
	docker run \
		--rm \
		--network="host" \
		-v "$(CURDIR):/usr/src" \
		$(SONAR_IMAGE) \
		-Dsonar.projectKey=$(SONAR_PROJECT) \
		-Dsonar.sources=. \
		-Dsonar.host.url=http://localhost:9000 \
		-Dsonar.token=$(SONAR_TOKEN)
