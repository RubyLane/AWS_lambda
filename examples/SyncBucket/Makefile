all: build/SyncBucket_handler.zip

deploy: deploy/handler

deploy/handler: build/SyncBucket_handler.zip
	mkdir -p deploy
	#aws lambda update-function-code --function-name SyncBucket --publish --zip-file fileb://build/SyncBucket_handler.zip
	aws lambda update-function-code --function-name SyncBucket --zip-file fileb://build/SyncBucket_handler.zip
	touch deploy/handler

build/SyncBucket_handler.zip: syncbucket.tcl
	mkdir -p build
	zip build/SyncBucket_handler.zip syncbucket.tcl

log:
	# Tails the CloudWatch logs for this function.  Lags about 10 seconds behind
	awslogs get -w -i 1 -G -S /aws/lambda/SyncBucket ALL

clean:
	-rm -rf deploy build
