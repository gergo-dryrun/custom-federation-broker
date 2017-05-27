MODULE:=lambda_login_generator

publish:
	rm -rf ./publish/$(MODULE)/
	mkdir -p ./publish/$(MODULE)
	cp -r ./$(MODULE) ./publish/
	pip install -t ./publish/$(MODULE) -r ./publish/$(MODULE)/requirements.txt
	cd ./publish/$(MODULE) && zip -r ../$(MODULE).zip .

clean:
	@echo "--> Cleaning pyc files"
	find . -name "*.pyc" -delete
	rm -rf ./publish
	@echo ""