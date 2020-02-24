# AWS_lambda
Tcl runtime for AWS Lambda and some layers for talking to AWS services and processing images

Documentation is still forthcoming, but the talk from the 2019 Tcl Conference should provide enough context to make sense of
the files available in this repo:

[![TclCon 2019 AWS Lambda Presentation](https://img.youtube.com/vi/VYz_SpCejio/0.jpg)](https://www.youtube.com/watch?v=VYz_SpCejio&start=2056)

Slides: [slides](https://rubylane.github.io/AWS_lambda/tcl_lambda.html)

## Examples

examples/HelloWorld: Minimal example that logs a message "hello, world" to cloudwatch when your lambda function runs.

examples/SyncBucket: Demonstrates handling an event from S3, accessing AWS services from your function (S3 in this case), and logging JSON documents so that advanced filtering is available on the logs,
