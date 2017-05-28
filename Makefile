MODULE:=lambda_login_generator

package_code:
	rm -rf code/publish/$(MODULE)/
	mkdir -p code/publish/$(MODULE)
	cp -r code/$(MODULE) code/publish/
	pip install -t code/publish/$(MODULE) -r code/publish/$(MODULE)/requirements.txt
	cd code/publish/$(MODULE) && zip -r ../$(MODULE).zip .

clean:
	@echo "--> Cleaning up from previous deployment."
	find . -name "*.pyc" -delete
	rm -rf code/publish
	rm -rf template/publish
	@echo ""

deps:
	@which jq || ( which brew && brew install jq || which apt-get && apt-get install jq || which yum && yum install jq || which choco && choco install jq)
	@which aws || pip install awscli

deploy: clean package_code deps
	mkdir -p template/publish
	aws cloudformation package --template-file template/login_generator.template --s3-bucket $(BUCKET_NAME) --s3-prefix lambda-login-generator/lambda --output-template-file template/publish/lambda-login-generator.template
	aws cloudformation deploy --template-file template/publish/lambda-login-generator.template --stack-name $(STACK_NAME) --capabilities CAPABILITY_NAMED_IAM
	make clean
