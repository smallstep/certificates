package majordomo

//go:generate protoc --proto_path=.. --go_out=.. --go-grpc_out=.. --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative linkedca/provisioners.proto linkedca/admin.proto
