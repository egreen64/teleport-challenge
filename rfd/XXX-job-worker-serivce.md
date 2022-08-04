---
authors: Eric Green (egreen64@yahoo.com)
state: draft
---

# RFD XX - Job Worker Service

## What

A job worker service that can start and stop arbitrary Linux processes. 

The job worker service will be implemented as a gRPC server that uses a golang job worker library which provides an interface for controlling the complete lifecycle of a job (linux process). The gRPC service will provide an API that can be used by an external CLI client. 

The gRPC service and CLI will use mTLS to provide mutual authentication to ensure that communications are trusted and secure. This requires the use of both client and server side x.509 certificates with a strong cipher suite. The job worker CLI will act as a gRPC client using mTLS as a transport to communicate securely with the job worker gRPC server.

Besides authentication as provided via mTLS, authorization will also be provided to validate that clients of the gRPC server are also authorized to use its services. Authorization checks will be made by the job worker library each time the gRPC service invokes the job worker library to perform a function.

Additionally, each job (linux process) will be isolated from other jobs by making use of Linux Namespaces. Specifically, each job will have a separate PID, MOUNT and Network namespace. 

Also, each job can be configured with a set of upper resource limits to control shared resource usage on the host where the job worker service runs. These upper resource limits will be used to control CPU, memory and disk utilization. These resource limits will be implemented using Linux Cgroups.

## Why

This job worker service is being implemented as part of a 1 week coding challenge for Teleport

## Details

### Scope

As part of this one week challenge it is expected that **ONLY** the job worker library is be implemented and tested. The implementation of the gRPC server and CLI implementations are not in scope. However, aspects of the gRPC server and CLI design are in scope.

Included in this design will be a proposed gRPC protobuf API as well example CLI commands.

### Build Assumptions

- The job worker library will be written in GoLang using go version 1.18.4.
- The gRPC golang protobuf bindings will be generated using the protobuf compiler, protoc version 3.21.4.
- It is expected that the aforementioned GoLang and protoc compilers are installed on the machine where the job worker library will be built.

### Runtime Assumptions

- Because the job worker library will be making calls to low-level operating system primitives, **root privileges** are required to run the gRPC server or any other program that makes use of this library.
- The job worker library and associated tests will be run and verified on an AWS EC2 instance running Ubuntu 22.04 LTS with Linux Kernel version 5.15.0-1015.
- Cgroups version 2 will also be used instead of Cgroups version 1.

### Protobuf Definition

The following is the proposed gRPC protobuf API used between the gRPC server and gRPC based CLI, but also closely resembles the interface implemented by the job worker library. The information contained within the protobuf should provide helpful to understand the parameters required to to start a job as well as the status information maintained by job worker for each job. 

```protobuf
syntax = "proto3";

package job_worker_api_v1;

option go_package = "egreen64/teleport-challenge/job_worker_api_v1";

/**
* This file contains the service definition for the Job Worker Service API.
*
* The service provides the ability to start/stop/query linux processes or jobs.
* The service allows for the the streaming of a job's output/error log while the job is running or even after it has been stopped
* The service will maintain a job's status and logs only for the lifetime of the service.
*/

/**
* Represents Job administrative state values
*
* JobAdminState indicates what operations have been performed by the end user - starting and/or stopping of a job
*/
enum JobAdminState {
    JOB_STARTED = 0;    //denotes Job has been started
    JOB_STOPPED = 1;    //denotes Job has been stopped
}

/**
* Represents Job operational status values
*
* JobOperStatus indicates the current status of a job - either pending, running or ended.
* A job could have a status of ended either because it completed on its own or because it was stopped by an end user.
* Looking at the associated JobExitStatus of a job will indicate how the job was ended
*/
enum JobOperStatus {
    JOB_PENDING = 0;    //denotes Job is in pending state
    JOB_RUNNING = 1;    //denotes Job is running
    JOB_ENDED   = 2;    //denotes Job has ended
}

/**
* Represents Job exit status values
*
* JobExitStatus indicates how a job ended - either normally or via a JobStopRequest
*/
enum JobExitStatus {
    JOB_EXITED_NORMALLY = 0;    //denotes Job ran to its normal completion
    JOB_EXITED_STOPPED  = 1;    //denotes Job was stopped while still running
}

/**
* Represents JobStartRequest
*
* JobStartRequest specifies the program to run and its associated parameters (if any) along with any configured upper resource limits 
* that should be imposed on the job. A value of -1 for any of the resource limits indicates that no upper limit will be enforced.
*/
message JobStartRequest {
    string program                      = 1;    //program name to run
    repeated string program_args        = 2;    //program arguments
    int32 memory_high_limit             = 3;    //high memory limit
    int32 cpu_high_limit                = 4;    //high cpu limit
    int32 disk_read_bytes_high_limit    = 5;    //high disk read limit in bytes/second
    int32 disk_write_bytes_high_limit   = 6;    //high disk write limit in bytes/second
}

/**
* Represents JobStartResponse
*
* JobStartResponse will be returned up successful completion of the JobStartRequest.
* The JobStartResponse contains the unique job identifier assigned to the job when it was started. 
* The job identifier is used on all subsequent job service API calls.
*/
message JobStartResponse {
    string job_id   = 1;    //job_id of started job
}

/**
* Represents JobStopRequest
*
* JobStopRequest specifies the job identifier of which job to stop.
*/
message JobStopRequest {
    string job_id   = 1;    //job_id of job to stop
}

/**
* Represents JobQueryRequest
*
* JobQueryRequest specifies the job identifier of which job to query.
*/
message JobQueryRequest {
    string job_id   = 1;    //job_id of job to query
}

/**
* Represents JobQueryResponse
*
* JobQueryResponse contains a job's configuration as specified in the JobStartRequest as well as its current state and status
*/
message JobQueryResponse {
    string job_id                       = 1;    //job_id of job
    JobAdminState admin_state           = 2;    //administrative state of job
    JobOperStatus oper_status           = 3;    //operational status of job
    JobExitStatus exit_status           = 4;    //exit status of job
    int32 job_exit_code                 = 5;    //job exit code (value valid only if oper_status == JOB_ENDED)
    string program                      = 6;    //program name 
    repeated string program_args        = 7;    //program arguments
    int32 memory_high_limit             = 8;    //high memory limit
    int32 cpu_high_limit                = 9;    //high cpu limit
    int32 disk_read_bytes_high_limit    = 10;   //high disk read limit
    int32 disk_write_bytes_high_limit   = 11;   //high disk write limit
}

/**
* Represents JobGetLogRecordsRequest
*
* JobGetJobGetLogRecordsRequest specifies the job identifier of which job to get the stream of JobLogRecord.
*/
message JobGetLogRecordsRequest {
    string job_id               = 1;    //job_id of job to get log records
}

/**
* Represents JobLogRecord
*
* JobLogRecord contains a single line from a job's output/error log.
*/
message JobLogRecord {
    string logRecord    = 1;    //job log record
}

/**
* Void response
*
* Void is returned by service functions that have no other data to return.
*/
message Void {
}

/**
* JobWorker service to control a job's life cycle and query its status and logs.
*/
service JobWorker {

    /**
    * StartJob will start the linux process as specified in the supplied JobStartRequest.
    * If the job cannot be successfully started an error will be generated.
    */
    rpc StartJob(JobStartRequest)  returns (JobStartResponse) {
    }

    /**
    * StopJob will stop the job specified in the JobStopRequest
    * If the job identifier in the JobStopRequest is unknown, an error with be generated
    */
    rpc StopJob(JobStopRequest)  returns (Void) {
    }

    /**
    * QueryJob queries the job configuration and status for the job specified in the JobQueryRequest.
    * If the job identifier in the JobQueryRequest is unknown, an error will be generated
    */
    rpc QueryJob(JobQueryRequest) returns (JobQueryResponse) {
    }

    /**
    * GetJobLogRecords streams the job log records for the job specified in the JobGetLogRecordsRequest.
    * If the job identifier in the JobGetLogRecordsRequest is unknown, and error will be generated
    */ 
    rpc GetJobLogRecords (JobGetLogRecordsRequest) returns (stream JobLogRecord) {
    }

}
```

### Job Worker Library Interface

The job worker library will provide an interface for controlling and monitoring the lifecycle of a job.

The interface will provide the capabilities to:
- Start a job
- Stop a job
- Query a job's status
- Get a job's output/err log

As mentioned prior, the job worker library will invoke an authorization check each time one of its interface functions is called.

The job worker library will maintain a list of jobs that are running or have completed, so that the status of each job as well as a job's log can be queried even after a job has completed. Each job will be represented in a job record. The list of job records will be maintained globally withing the job worker library. The access to this global list will be controlled by a mutex to avoid race conditions. 

#### Start Job

When the job work library starts a job, after performing the required authorization call, it will perform the following steps, and generate any errors if these steps are completed successfully:

1. Create a job record with a unique job identifier with all program, parameters and resource limits
1. Set the job's administrative status to STARTED and its operational status to PENDING
1. Create a network name space to be used by the job using the unix.Mount, unix.Unshare and unix.SetNs calls using unix.CLONE_NEWNET namespace
1. Create new mount and pid namespaces for the job by setting the sys proc attributes of the job - syscall.CLONE_NEWPID | syscall.CLONE_NEWNS
1. Sets the hostname for job via the syscall.Sethostname function
1. Create and configure Cgroups for CPU, Memory and Disk limits by modifying cgroup files in /sys/fs/cgroup/cpu, /sys/fs/cgroup/memory and /sys/fs/cgroup/io respectively.
1. Set the PID in the job record for the job. This PID is the PID of the job as the host sees it and not the PID within the job's PID namespace
1. Unshare host mount name space and mount a new proc filesystem into job's mount name space via syscall.Mount 
1. Enable the local loopback interface in the jobs network namespace using the netlink package and the function netlink.LinkSetUp()
1. Create a command to run the job's program including any optional program arguments
1. Create a temporary file to hold the jobs output and error log records
1. Create a pipe to capture the command's stdout and assign this same pipe to capture the command's stderr
1. Create a work group and increment the work groups counter by one
1. Create a go routine that will capture the command's output from the pipe and write the capture lines to the temporary file. The go routine will terminate upon the close of the command's stdout which occurs when the job terminates. Upon completion of the go routine, the routine will indicate to the workgroup that it is done.
1. Start the command for the job
1. Set the job's operational status to RUNNING
1. Wait on completion of the work group - which indicates the job/process has completed and that stdout and stderr have been completely read
1. Wait on command completion
1. Set the job's exit status and exit code
1. Set the job's operational status to ENDED
1. Unmount the proc file system
1. Remove the job's network namespace 

#### Stop Job

When the job work library stops a job, after performing the required authorization call, it will perform the following steps:

1. Validate the job id against the list of job records, and if not found return a job not found error
1. Set the job's administrative status to stopped.
1. Issue the Stop function against the job's command 

#### Query Job Status

When the job work library is queried for a job, after performing the required authorization call, it will perform the following steps:

1. Validate the job id against the list of job records, and if not found return a job not found error
2. Return the job record information for the requested job

#### Get Job Log

Besides being passed a context and job id, a user supplied channel will also be supplied. This channel will be read by the caller to receive streaming job log records from the job worker library.

The implementation of this function allows for multiple clients/callers at the same time to query the job logs for the same job or different jobs.

When the job work library is asked for a job's log, after performing the required authorization call, it will perform the following steps:

1. Validate the job id against the list of job records, and if not found return a job not found error
1. Crete a command to invoke the Linux `tail -f -n +1 --pid=XXXX <job log file>`  where XXXX is the PID of the job and `<job log file>` is the temporary file where the job's log file is stored. This command will read all job records from the beginning of the job's log record file until the process ends. If the process has already ended, then the command will just return the contents for the job's log record file and then end. Otherwise, if the job is still running, the command will continue to stream new records generated by the job.
1. Create a pipe to capture the command's stdout
1. Create a wait group and increment its count by one.
1. Start a go routine that will read from the pipe. The go routine will read all records from the pipe and write these records out to a go channel supplied to the Get Job Log function call. The go routine will run for as long as the tail command is running. When the tail command ends (because the job process ends), the go routine will close the go channel to indicate to the caller that there are no more job log records. The go routine upon ending will also indicate to the work group that it is done.
1. Wait upon the workgroup to be done
1. Wait upon the tail command to be done.

### Transport Security

As mentioned mTLS will be used for secure communications between the gRPC job worker server and gRPC job worker client - CLI. 

#### TLS Version

TLS version 1.3 will be used between the gRPC server and the CLI. Being that the client and server are both being internally developed, going with version 1.3 vs version 1.2 make sense as TLS 1.3 provides more security and quicker handshake times.

#### X.509 Certificates

For the purpose of this coding challenge self-signed certificates will be used for both the client and server certificates. Both the client and server certificates will be signed by a self-signed Root CA (certificate authority).

In a production environment, ideally an external trusted ROOT CA would be used, e.g. LetsEncrypt, Digicert, etc. to issue and sign the client and server certificates.

The TLS configuration for both the client and server will need to include the same self-signed Root CA as part of their respective CA cert pools.

#### Cipher Suites

Since version 1.3 of TLS will be used, one of the following Cipher Suites would be used:  
- TLS_AES_128_GCM_SHA256
- TLS_AES_256_GCM_SHA384
- TLS_CHACHA20_POLY1305_SHA256 

However, since go version 1.12, when version 1.3 of TLS was implemented, the selection of which Cipher Suites to use were not configurable as per this [link](https://go.dev/blog/tls-cipher-suites#:~:text=When%20we%20implemented%20TLS%201.3%20in%20Go%201.12%2C%20we%20didn%E2%80%99t%20make%20TLS%201.3%20cipher%20suites%20configurable)

#### Authentication

Mutual authentication will occur by mTLS via the exchange and verification of the client and server certificates.

### Authorization

##### Authorization Library

A simple authorization library (package) will be implemented with a single function, e.g. **isAuthorized**, to determine whether or not a user is authorized to access the system. The **isAuthorized** function will accept as input the user's client certificate and will compare the certificate's Subject field against a pre-defined list of Subjects. If the user's Subject field is found in the list, then the **isAuthorized** function will return **true**, otherwise it will return **false**

##### Job Worker Library

The job worker library will invoke the aforementioned **isAuthorized** function from the authorization library on each interface call to protect the library against unauthorized access. 

This means that the client certificate will need to be passed into each of the library functions. This will be done via a golang context where the context will contain a reference to the client certificate, and the context will be passed in as the first parameter to each of the job worker interface functions.

##### gRPC Server

In the implementation of the gRPC server, the server will use the [google.golang.org/grpc/peer ](https://pkg.go.dev/google.golang.org/grpc/peer) package in order to obtain the client certificate. The use of this package will allow each gRPC service function to obtain the client certificate from the gRPC context passed to it. A new context containing the client certificate should be created and then passed, as mentioned above, to the job work library functions.

### CLI

The CLI client will provide the following command set to manage and monitor job worker jobs:
- `jw job start <command> [args...] [-clim limit] [-mlim limit] [-drlim limit] [-dwlim limit]`
    - `<command>` specifies the linux command or program to run
    - `[args...]` specifies zero or more optional program arguments
    - `-clim` specifies upper CPU limit
    - `-mlim` specifies upper Memory limit
    - `-drlim` specifies upper disk read limit in bytes/second`
    - `-dwlim` specifies upper disk write limit in bytes/second`
- `jw job stop <job-id>`
    - `<job_id>` specifies the id of the job to stop
- `jw job info <job-id>`
    - `<job_id>` specifies the id of the job to get information
- `jw job log <job-id>`
    - `<job_id>` specifies the id of the job to get job logs
