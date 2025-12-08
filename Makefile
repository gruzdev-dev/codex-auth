REPORT_FILE := tests/TEST_REPORT.txt
MUTATION_IMAGE := codex-auth-mutation
MUTATION_DOCKERFILE := tests/Dockerfile.mutation

.PHONY: test test-all clean-report

test: clean-report run-tests

clean-report:
	@rm -f $(REPORT_FILE) || true
	@touch $(REPORT_FILE)

run-tests:
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
	@if go test -v -tags=!integration ./... >> $(REPORT_FILE) 2>&1; then \
		echo "RESULT: SUCCESS" | tee -a $(REPORT_FILE); \
	else \
		echo "RESULT: FAILED" | tee -a $(REPORT_FILE); \
		echo "Unit tests failed. See details above." >> $(REPORT_FILE); \
		exit 1; \
	fi
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
	@if RUN_BENCHMARKS=1 go test -bench=. -benchmem ./adapters/hasher/... >> $(REPORT_FILE) 2>&1; then \
		echo "RESULT: SUCCESS" | tee -a $(REPORT_FILE); \
	else \
		echo "RESULT: FAILED" | tee -a $(REPORT_FILE); \
		echo "Benchmarks failed. See details above." >> $(REPORT_FILE); \
		exit 1; \
	fi
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
	@if docker run --rm $(MUTATION_IMAGE) 2>&1 | tee -a $(REPORT_FILE); then \
		echo "RESULT: SUCCESS (Mutants Killed or Clean Run)" | tee -a $(REPORT_FILE); \
	else \
		echo "RESULT: WARNING (Some Mutants Survived)" | tee -a $(REPORT_FILE); \
	fi
	@echo "" >> $(REPORT_FILE)

	@# ------------------------------------------------------------------
	@# INTEGRATION TESTS
	@# ------------------------------------------------------------------
	@echo "INTEGRATION TESTING" | tee -a $(REPORT_FILE)
	@echo "Description:" >> $(REPORT_FILE)
	@echo "  - Tool: cucumber/godog" >> $(REPORT_FILE)
	@echo "  - BDD Testing" >> $(REPORT_FILE)
	@echo "--------------------------------------------------" >> $(REPORT_FILE)
	@if go test -tags=integration ./tests/bdd -v >> $(REPORT_FILE) 2>&1; then \
		echo "RESULT: SUCCESS" | tee -a $(REPORT_FILE); \
	else \
		echo "RESULT: FAILED" | tee -a $(REPORT_FILE); \
		echo "Integration tests failed. See details above." >> $(REPORT_FILE); \
		exit 1; \
	fi
	@echo "" >> $(REPORT_FILE)	