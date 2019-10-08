package_template = ./package.yaml
lamdba_root = ./cmd
lambda_paths = $(shell find $(lamdba_root) -name main.go -print0 | xargs -0 -n1 dirname | sort --unique)
event_path = ./events/
stack = jd-serverless

.PHONY: bpd deploy build-all build zip invoke start

bpd: build-all package deploy

pd: package deploy

deploy:
	sam deploy --template-file $(package_template) --stack-name $(stack) --capabilities CAPABILITY_NAMED_IAM

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(lambda)/main $(lambda)/main.go
	zip $(lambda)/main.zip $(lambda)/main

build-all:
	for lambda_path in $(lambda_paths); do \
		make build lambda=$$lambda_path ; \
	done

package:
	sam package --output-template-file $(package_template) --s3-bucket ts-serverless

invoke:
	sam local invoke $(func) --event $(event_path)$(event)

start:
	sam local start-api -p 9000