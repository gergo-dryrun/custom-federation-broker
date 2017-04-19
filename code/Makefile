publish: clean
	rm -rf ./publish/temp_login/
	mkdir -p ./publish/temp_login
	cp -r ./temp_login ./publish/
	pip install -t ./publish/temp_login -r ./publish/temp_login/requirements.txt
	cd ./publish/temp_login && zip -r ../temp_login.zip .
clean:
	@echo "--> Cleaning pyc files"
	find . -name "*.pyc" -delete
	rm -rf ./publish
	@echo ""
