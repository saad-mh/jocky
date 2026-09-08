; ModuleID = "hello"
target triple = "unknown-unknown-unknown"
target datalayout = ""

declare void @"report"(i8* %".1")

declare i8* @"procs_list"()

declare i64 @"proc_count"(i8* %".1")

declare i8* @"proc_name"(i8* %".1", i64 %".2")

declare i64 @"proc_pid"(i8* %".1", i64 %".2")

declare void @"proc_kill"(i64 %".1")

declare i8* @"proc_mem_read"(i64 %".1", i64 %".2", i64 %".3")

declare i8* @"net_conns"()

declare i8* @"net_sniff"(i64 %".1")

declare i8* @"reg_read"(i8* %".1", i8* %".2")

declare i8* @"reg_list"(i8* %".1")

declare i8* @"file_list"(i8* %".1")

declare i8* @"file_read"(i8* %".1")

declare i8* @"sys_info"()

declare i8* @"hash_file"(i8* %".1")

declare i32 @"strcmp"(i8* %".1", i8* %".2")

define void @"start"()
{
entry:
  %"strptr" = getelementptr inbounds [18 x i8], [18 x i8]* @".jk_str.0", i32 0, i32 0
  call void @"report"(i8* %"strptr")
  %"strptr.1" = getelementptr inbounds [27 x i8], [27 x i8]* @".jk_str.1", i32 0, i32 0
  call void @"report"(i8* %"strptr.1")
  ret void
}

@".jk_str.0" = internal constant [18 x i8] c"Hello from JOCKY!\00"
@".jk_str.1" = internal constant [27 x i8] c"JOCKY compiler is working.\00"