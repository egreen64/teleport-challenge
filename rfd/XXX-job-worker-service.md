---
authors: Eric Green
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

This job worker service is being implemented as part of a 2 week coding challenge for Teleport

## Details

### Scope

As part of this two week challenge it is expected that the job worker library, gRPC server and CLI be implemented and tested. 

Included in this design will be a proposed gRPC protobuf API as well proposed CLI commands.

### Build Assumptions

- The job worker library, gRPC Server and CLI will be written in GoLang using go version 1.18.4.
- The gRPC golang protobuf bindings will be generated using the protobuf compiler, protoc version 3.21.4.
- It is expected that the aforementioned GoLang and protoc compilers are installed on the machine where the job worker library will be built.

### Runtime Assumptions

- Because the job worker library will be making calls to low-level operating system primitives, **root privileges** are required to run the gRPC server or any other program that makes use of this library.
- The Job Worker library, gRPC server, CLI and associated tests will be run and verified on an AWS EC2 instance running Ubuntu 22.04 LTS with Linux Kernel version 5.15.0-1015.
- Cgroups version 2 will also be used instead of Cgroups version 1.

### Protobuf Definition

The following is the proposed gRPC protobuf API used between the gRPC server and gRPC based CLI, but also closely resembles the interface implemented by the job worker library. The information contained within the protobuf should provide helpful to understand the parameters required to to start a job as well as the status information maintained by job worker for each job. 

```protobuf
syntax = "proto3";

package job_worker_api_v1;

option go_package = "gihub.com/egreen64/teleport-challenge/job_worker_api_v1";

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
    JOB_ADMIN_STATE_UNSPECIFIED = 0;    //denotes unspecified admin state
    JOB_ADMIN_STATE_STARTED     = 1;    //denotes Job has been started
    JOB_ADMIN_STATE_STOPPED     = 2;    //denotes Job has been stopped
}

/**
* Represents Job operational status values
*
* JobOperStatus indicates the current status of a job - either pending, running or ended.
* A job could have a status of ended either because it completed on its own or because it was stopped by an end user.
* Looking at the associated JobExitStatus of a job will indicate how the job was ended
*/
enum JobOperStatus {
    JOB_OPER_STATUS_UNSPECIFIED = 0;    //denotes unspecified oper status
    JOB_OPER_STATUS_PENDING     = 1;    //denotes Job is in pending state
    JOB_OPER_STATUS_RUNNING     = 2;    //denotes Job is running
    JOB_OPER_STATUS_ENDED       = 3;    //denotes Job has ended
}

/**
* Represents Job exit status values
*
* JobExitStatus indicates how a job ended - either normally or via a JobStopRequest
*/
enum JobExitStatus {
    JOB_EXIT_STATUS_UNSPECIFIED     = 0;    //denotes unspecified exit status
    JOB_EXIT_STATUS_EXITED_NORMALLY = 1;    //denotes Job ran to its normal completion
    JOB_EXIT_STATUS_EXITED_STOPPED  = 2;    //denotes Job was stopped while still running
}

/***
* Represents JobConfig
*
* JobConfig specifies the program to run and its associated parameters (if any) along with any configured upper resource limits 
* that should be imposed on the job. A value of 0 for any of the resource limits indicates that no upper limit will be enforced.
*/
message JobConfig {
    string program                      = 1;    //program name to run
    repeated string program_args        = 2;    //program arguments
    uint32 memory_limit_high            = 3;    //memory upper limit in bytes
    uint32 cpu_limit_quota              = 4;    //cpu limit quota in microseconds
    uint32 cpu_limit_period             = 5;    //cpu limit period microseconds
    uint32 disk_limit_read_bytes_high   = 6;    //high disk read limit in bytes/second
    uint32 disk_limit_write_bytes_high  = 7;    //high disk write limit in bytes/second
}

/**
* Represents JobStartRequest
*
* JobStartRequest specifies the program to run and its associated parameters (if any) along with any configured upper resource limits 
* that should be imposed on the job. A value of 0 for any of the resource limits indicates that no upper limit will be enforced.
*/
message JobStartRequest {
    JobConfig job_info = 1;   // contains the job information used to start the job
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
* Represents JobStopResponse
*
*/
message JobStopResponse {
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
    JobConfig job_config                = 2;    //job configuration for the queried job
    JobAdminState admin_state           = 3;    //administrative state of job
    JobOperStatus oper_status           = 4;    //operational status of job
    JobExitStatus exit_status           = 5;    //exit status of job
    int32 job_exit_code                 = 6;    //job exit code (value valid only if oper_status == JOB_ENDED)          
}

/**
* Represents JobGetLogRecordsRequest
*
* JobGetJobGetLogRecordsRequest specifies the job identifier of which job to get the stream of JobLogRecord.
*/
message JobGetLogRecordsRequest {
    string job_id               = 1;    //job_id of job to get log records
    bool continuous_stream      = 2;    //log records will continue to stream until job end
}

/**
* Represents JobLogRecord
*
* JobLogRecord contains a single line from a job's output/error log.
*/
message JobLogRecord {
    bytes logRecord    = 1;    //job log record
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
    rpc StopJob(JobStopRequest)  returns (JobStopResponse) {
    }

    /**
    * QueryJob queries the job configuration and status for the job specified in the JobQueryRequest.
    * If the job identifier in the JobQueryRequest is unknown, an error will be generated
    */
    rpc QueryJob(JobQueryRequest) returns (JobQueryResponse) {
    }

    /**
    * GetJobLogRecords streams the job log records, both stdout and stderr, for the job specified in the JobGetLogRecordsRequest.
    * If the job identifier in the JobGetLogRecordsRequest is unknown, and error will be generated
    */ 
    rpc GetJobLogRecords (JobGetLogRecordsRequest) returns (stream JobLogRecord) {
    }

}
```

### Job Worker Library Interface

The job worker library will provide an interface for controlling and monitoring the lifecycle of a job.

The interface will provide the capabilities to:
- Instantiate new Job Worker library
- Start a job
- Stop a job
- Query a job's status
- Get a job's output/err log
- Respawned

The following is a skeletal draft version of the Job Worker Package:

```go
package jobworker

import (
	"context"
	"fmt"
	"log"

	"github.com/google/uuid"
)

type JobId string

type JobAdminState int32

const (
	JOB_ADMIN_STATE_UNSPECIFIED JobAdminState = 0 //denotes unspecified admin state
	JOB_ADMIN_STATE_STARTED     JobAdminState = 1 //denotes Job has been started
	JOB_ADMIN_STATE_STOPPED     JobAdminState = 2 //denotes Job has been stopped
)

type JobOperStatus int32

const (
	JOB_OPER_STATUS_UNSPECIFIED JobOperStatus = 0 //denotes unspecified oper status
	JOB_OPER_STATUS_PENDING     JobOperStatus = 1 //denotes Job is in pending state
	JOB_OPER_STATUS_RUNNING     JobOperStatus = 2 //denotes Job is running
	JOB_OPER_STATUS_ENDED       JobOperStatus = 3 //denotes Job has ended
)

type JobExitStatus int32

const (
	JOB_EXIT_STATUS_UNSPECIFIED     JobExitStatus = 0 //denotes unspecified exit status
	JOB_EXIT_STATUS_EXITED_NORMALLY JobExitStatus = 1 //denotes Job ran to its normal completion
	JOB_EXIT_STATUS_EXITED_STOPPED  JobExitStatus = 2 //denotes Job was stopped while still running
)

type JobConfig struct {
	Program                 string
	ProgramArgs             []string
	MemoryLimitHigh         uint32
	CpuLimitQuota           uint32
	CpuLimitPeriod          uint32
	DiskLimitReadBytesHigh  uint32
	DiskLimitWriteBytesHigh uint32
}

type JobInfo struct {
	JobId       JobId
	JobInfo     *JobConfig
	AdminState  JobAdminState
	OperStatus  JobOperStatus
	ExitStatus  JobExitStatus
	JobExitCode int32
}

type JobWorkerAuth interface {
	IsAuthorized(user string, org string, oper string) bool
}

type jobWorker struct {
	jobAuth  JobWorkerAuth
	jobInfos map[JobId]JobInfo
}

func New(authLib JobWorkerAuth) *jobWorker {
	jobInfos := make(map[JobId]JobInfo)

	return &jobWorker{
		jobAuth:  authLib,
		jobInfos: jobInfos,
	}
}

func (jw *jobWorker) StartJob(ctx context.Context, jobInfo *JobConfig) (string, error) {
	oper := "StartJob"
	if !jw.jobAuth.IsAuthorized(getUserKey(ctx), getOrganizationKey(ctx), oper) {
		return "", fmt.Errorf("%s:%s not authorized to perform %s", getUserKey(ctx), getOrganizationKey(ctx), oper)
	}

	jobId := "Job-" + uuid.New().String()

	return jobId, nil
}

func (jw *jobWorker) StopJob(ctx context.Context, jobId string) error {
	oper := "StopJob"
	if !jw.jobAuth.IsAuthorized(getUserKey(ctx), getOrganizationKey(ctx), oper) {
		return fmt.Errorf("%s:%s not authorized to perform %s", getUserKey(ctx), getOrganizationKey(ctx), oper)
	}
	return nil
}

func (jw *jobWorker) QueryJob(ctx context.Context, jobId string) (*JobInfo, error) {
	oper := "QueryJob"
	if !jw.jobAuth.IsAuthorized(getUserKey(ctx), getOrganizationKey(ctx), oper) {
		return nil, fmt.Errorf("%s:%s not authorized to perform %s", getUserKey(ctx), getOrganizationKey(ctx), oper)
	}
	return &JobInfo{}, nil
}

func (jw *jobWorker) StreamLog(ctx context.Context, jobId string, logStream *chan string) error {
	oper := "StreamLog"
	if !jw.jobAuth.IsAuthorized(getUserKey(ctx), getOrganizationKey(ctx), oper) {
		return fmt.Errorf("%s:%s not authorized to perform %s", getUserKey(ctx), getOrganizationKey(ctx), oper)
	}
	return nil
}

func Respawned() {
	log.Println("Respawned called")
}
```
#### Instantiate Job Library

Before any jobs can be managed, the first Job Worker library function that needs to be invoked is **New**. 

As mentioned prior, the job worker library will invoke an authorization check each time one of its interface functions is called. The Job Worker library **New** method takes as input an instance of an authorization package that implements a Job Worker Library authorization interface. This allows the user of the job worker library to provide an authorization library of their choosing as long as the library implements the Job Worker Library authorization interface:

```go
type JobWorkerAuth interface {
	IsAuthorized(user string, org string, oper string) bool
}
```

The job worker library will maintain a list of jobs that are running or have completed, so that the status of each job as well as a job's log can be queried even after a job has completed. Each job will be represented by a job info record. The list of job info records will be maintained in the context of the job worker library instance, allowing for each library instance to maintain its own list of job info records. The access to this list will be controlled by a mutex to avoid race conditions. 

#### Start Job

When the job work library starts a job, after performing the required authorization call, it will perform the following steps, and generate any errors if these steps are completed successfully:

1. Create a job info record with a unique job identifier with all program, parameters and resource limits
1. Set the job's administrative status to STARTED and its operational status to PENDING
1. New mount, pid, network and UTS namespaces for the job need to be created in order to isolate the job from other jobs. In order to create these new namespaces the calling process will be respawned by cloning it via the go exec.Command `/proc/self/exe jobworker run <command> <command args>` and setting the sys proc attributes of the command - syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWNET | syscall.CLONE_NEWUTS. The respawned process will have new namespaces and will be the parent process of the actual job command.
1. Set the stdout of the exec.Command to a reference of a go bytes.Buffer. When the command completes, this buffer will contain the exit code and exit status of the actual command as written by the parent process to stdout.
1. Set the job's operational status to RUNNING
1. Call the Start Function of the exec.Command 
1. Save the PID of the newly spawned parent process. This PID is the PID of the parent process as the host sees it and not the PID within the parent process's PID namespace. This pid will be used by the JobStop function to locate the parent process's child process - job command.
1. Call the Wait function of the exec.Command and wait for the parent process to end.
1. Set the job's exit and exited status from the bytes.Buffer
1. Set the job's operational status to ENDED

Because the respawn operation causes the the user's main function to be invoked, the user will need to call the Job Worker library `Respawned` function to allow the Job Worker library to continue the job start operation.

#### Respawned

When this function is invoked, it will be running in the context of the parent process of the job command to be run.  The `Respawned` function will continue the process of starting the job command by performing the following steps:

1. Sets the hostname for job via the syscall.Sethostname function
1. Create and configure Cgroups for CPU, Memory and Disk limits by modifying cgroup files in /sys/fs/cgroup/cpu, /sys/fs/cgroup/memory and /sys/fs/cgroup/io respectively. The following cgroup attributes will be updated based on the limits passed into JobStart function:
    1. Memory - **/sys/fs/cgroup/memory/jw/`<job_id>`/memory.limit_in_bytes**
    2. CPU - **/sys/fs/cgroup/cpu/jw/`<job_id>`/cpu.cfs_period_us** and **/sys/fs/cgroup/cpu/jw/`<job_id>`/cpu.cfs_quota_us**
    2. Disk - **/sys/fs/group/io/jw/`<job_id>`/io.max**
1. Enable the local loopback interface in the jobs network namespace.
1. Create a go exec.Command to run the job's command including any optional command arguments. The job's command and command arguments are obtained from os.Args as these were passed as parameters of the `/proc/self/exe` respawn command.
1. Create a temporary job log file to hold the job's stdout and stderr messages and assign the file to both the command's stdout and stderr
1. Start the command for the job
1. Wait on command completion
1. Write the job's exit code and exit status to stdout

#### Stop Job

When the job work library stops a job, after performing the required authorization call, it will perform the following steps:

1. Validate the job id against the list of job info records, and if not found return a job not found error
1. Set the job's administrative status to stopped.
1. Kill the job by getting the child PID of the parent process (re-spawned process) and invoking syscall.Kill(). The parent's PID, which was previously saved during JobStart, is used in getting the child pid from the proc filesystem at `/proc/<parent_pid>/task/<parent_pid>/children`

#### Query Job Status

When the job work library is queried for a job, after performing the required authorization call, it will perform the following steps:

1. Validate the job id against the list of job info records, and if not found return a job not found error
2. Return the job info record information for the requested job

#### Get Job Log

Besides being passed a context and job id, a user supplied channel will also be supplied. This channel will be read by the caller to receive streaming job log records from the job worker library. The job worker library will stream job log records to the channel, and when the job command ends this function will close the channel.

The implementation of this function allows for multiple clients/callers at the same time to query the job logs for the same job or different jobs.

When the job work library is asked for a job's log, after performing the required authorization call, it will perform the following steps:

1. Validate the job id against the list of job info records, and if not found return a job not found error
1. Initialize total log file bytes read to zero
1. In a polling loop perform the following:
    1. Open job log file
    1. Seek to the file location of total log bytes re ad
    1. Read the job log file, one line at a time and write each record to the user's supplied go channel until EOF
    1. Close log file
    1. Update the total log file bytes read from the file. 
    1. Wait for 1 second
    1. If job operational is ENDED, break loop
1. Open job log file
1. Seek to the file location of total log bytes read
1. Read the job log file, one line at a time and write each record to the user's supplied go channel until EOF
1. Close log file
1. Close user supplied go channel to indicate to user that there are no more log messages 

An alternative approach to having a polling loop would be to use the **inotify** api to get notifications when the job's log file is updated.

### Transport Security

As mentioned mTLS will be used for secure communications between the gRPC job worker server and gRPC job worker client - CLI. 

#### TLS Version

TLS version 1.3 will be used between the gRPC server and the CLI. Being that the client and server are both being internally developed, going with version 1.3 vs version 1.2 make sense as TLS 1.3 provides more security and quicker handshake times.

#### X.509 Certificates

For the purpose of this coding challenge self-signed certificates will be used for both the client and server certificates. Both the client and server certificates will be signed by a self-signed Root CA (certificate authority). The algorithm and key length is RSA and 2048, respectively.

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

A simple authorization library (package) will be implemented with a single function, e.g. **isAuthorized**, to determine whether or not a user is authorized to access specific library functions. The **isAuthorized** function will accept as input a tuple of the client's username and organization as well as the library operation (Start, Stop, Query, GetLogRecords) and will compare this  tuple against a pre-defined list of tuples. If the tuple is found in the list, then the **isAuthorized** function will return **true**, otherwise it will return **false**

##### Job Worker Library

The job worker library will invoke the aforementioned **isAuthorized** function from the supplied authorization library on each job worker library function call to protect the job worker library against unauthorized access. 

This means that the client's username and organization will need to be passed into each of the library functions. This will be done via a golang context where the context will contain the username and organization. The context will be passed in as the first parameter to each of the job worker interface functions. 

The Job Worker library will provide a helper function to create the context with the username and organization.

##### gRPC Server

In the implementation of the gRPC server, the server will use the [google.golang.org/grpc/peer ](https://pkg.go.dev/google.golang.org/grpc/peer) package in order to obtain the client certificate. The use of this package will allow each gRPC service function to obtain the client certificate from the gRPC context passed to it. 

A new context containing the **Common Nme (CN)** and **Organization (0)** from client certificates's Subject field should be created and then passed, as mentioned above, to the job work library functions. The **CN** and **O** fields contain the client's username and organization fields, respectively. 

Here is a gRPC server code snippet showing how to obtain the clients certificate's CN and O fields:

```go
p, ok := peer.FromContext(ctx)
if !ok {
    return status.Error(codes.Unauthenticated, "no peer found")
}

tlsAuth, ok := p.AuthInfo.(credentials.TLSInfo)
if !ok {
    return status.Error(codes.Unauthenticated, "unexpected peer transport credentials")
}

if len(tlsAuth.State.VerifiedChains) == 0 || len(tlsAuth.State.VerifiedChains[0]) == 0 {
    return status.Error(codes.Unauthenticated, "could not verify peer certificate")
}

// Get Subject CN and O fields
if tlsAuth.State.VerifiedChains[0][0].Subject.CommonName != a.Username {
    return status.Error(codes.Unauthenticated, "invalid subject common name")
}

userName := tlsAuth.State.VerifiedChains[0][0].Subject.CommonName
organization := tlsAuth.State.VerifiedChains[0][0].Subject.Organization
```

### CLI

The CLI client will provide the following command set to manage and monitor job worker jobs:

- `jw job start <command> [args...] [-cquota limit] [-cperiod limit] [-mlim limit] [-drlim limit] [-dwlim limit]`
    - `<command>` specifies the linux command or program to run
    - `[args...]` specifies zero or more optional program arguments
    - `-cquota` specifies the CPU quota limit in microseconds
    - `-cperiod` specifies the CPU period limit in microseconds
    - `-mlim` specifies upper Memory limit in bytes
    - `-drlim` specifies upper disk read limit in bytes/second`
    - `-dwlim` specifies upper disk write limit in bytes/second`
- `jw job stop <job-id>`
    - `<job_id>` specifies the id of the job to stop
- `jw job info <job-id>`
    - `<job_id>` specifies the id of the job to get information
- `jw job log [-f] <job-id>`
    - `<job_id>` specifies the id of the job to get job logs
    - `[-f]` specifies to stream job output until job ends
