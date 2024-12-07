test:
	go test -v -coverprofile=testCoverage.out .
	go tool cover -html=testCoverage.out
.PHONY: test