# GO microservice example with simple hello world

## Docker build
On project folder
`sudo docker build -t go-hello:v1 . -f kubernetes/docker/Dockerfile`

## Docker run
To run interactively at the port 8080
`sudo docker run -it -p 8080:8080 go-hello:v1`
## GO Init
Run `go mod init hello.com/hello/v2` for module initialization.
This step is needed prior to fetch all the dependencies.
The dependencies are fetched with command `go get -u github.com/go-kit/examples/addsvc/pkg/addendpoint`
where `github.com/go-kit/examples/addsvc/pkg/addendpoint` is the dependency

## Image size
Check the image size with `sudo docker image ls | grep go-hello`. 
It could be around 10.5MB.
