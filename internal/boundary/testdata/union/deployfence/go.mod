module github.com/conductorone/apphub

go 1.25.0

require (
	cloud v0.0.0
	github.com/Azure/azure-sdk-for-go v0.0.0
	github.com/aws/aws-sdk-go-v2 v0.0.0
	k8s.io/api v0.0.0
)

replace cloud => ./nodotstub

replace github.com/Azure/azure-sdk-for-go => ./vendorstub

replace github.com/aws/aws-sdk-go-v2 => ./awsstub

replace k8s.io/api => ./k8sstub
