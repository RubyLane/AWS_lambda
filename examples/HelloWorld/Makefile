all: build/HelloWorld_handler.zip

deploy: deploy/handler

deploy/handler: build/HelloWorld_handler.zip
	mkdir -p deploy
	#aws lambda update-function-code --function-name HelloWorld --publish --zip-file fileb://build/HelloWorld_handler.zip
	aws lambda update-function-code --function-name HelloWorld --zip-file fileb://build/HelloWorld_handler.zip
	touch deploy/handler

build/HelloWorld_handler.zip: helloworld.tcl
	mkdir -p build
	zip build/HelloWorld_handler.zip helloworld.tcl

log:
	# Tails the CloudWatch logs for this function.  Lags about 10 seconds behind
	awslogs get -w -i 1 -G -S /aws/lambda/HelloWorld ALL

clean:
	-rm -rf deploy build
