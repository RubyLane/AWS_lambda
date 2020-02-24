proc handler {event context} {
	# This will show up in the AWS CloudWatch log group /aws/lambda/HelloWorld
	puts stderr "hello, world"
}

