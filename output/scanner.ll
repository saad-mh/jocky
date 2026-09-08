; ModuleID = "scanner"
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

define i1 @"scan"(i8* %"target")
{
entry:
  %"target.1" = alloca i8*
  store i8* %"target", i8** %"target.1"
  %"procs" = alloca i8*
  %"calltmp" = call i8* @"procs_list"()
  store i8* %"calltmp", i8** %"procs"
  %"total" = alloca i64
  %"procs.1" = load i8*, i8** %"procs"
  %"calltmp.1" = call i64 @"proc_count"(i8* %"procs.1")
  store i64 %"calltmp.1", i64* %"total"
  %"i" = alloca i64
  store i64 0, i64* %"i"
  br label %"loop_cond"
loop_cond:
  %"i.1" = load i64, i64* %"i"
  %"total.1" = load i64, i64* %"total"
  %"ilt" = icmp slt i64 %"i.1", %"total.1"
  br i1 %"ilt", label %"loop_body", label %"loop_exit"
loop_body:
  %"name" = alloca i8*
  %"procs.2" = load i8*, i8** %"procs"
  %"i.2" = load i64, i64* %"i"
  %"calltmp.2" = call i8* @"proc_name"(i8* %"procs.2", i64 %"i.2")
  store i8* %"calltmp.2", i8** %"name"
  %"name.1" = load i8*, i8** %"name"
  %"target.2" = load i8*, i8** %"target.1"
  %"strcmpres" = call i32 @"strcmp"(i8* %"name.1", i8* %"target.2")
  %"streq" = icmp eq i32 %"strcmpres", 0
  br i1 %"streq", label %"then", label %"else"
loop_exit:
  ret i1 0
then:
  ret i1 1
else:
  br label %"merge"
merge:
  %"i.3" = load i64, i64* %"i"
  %"addtmp" = add i64 %"i.3", 1
  store i64 %"addtmp", i64* %"i"
  br label %"loop_cond"
}

define void @"start"()
{
entry:
  %"strptr" = getelementptr inbounds [14 x i8], [14 x i8]* @".jk_str.0", i32 0, i32 0
  call void @"report"(i8* %"strptr")
  %"strptr.1" = getelementptr inbounds [12 x i8], [12 x i8]* @".jk_str.1", i32 0, i32 0
  %"calltmp" = call i1 @"scan"(i8* %"strptr.1")
  br i1 %"calltmp", label %"then", label %"else"
then:
  %"strptr.2" = getelementptr inbounds [21 x i8], [21 x i8]* @".jk_str.2", i32 0, i32 0
  call void @"report"(i8* %"strptr.2")
  br label %"merge"
else:
  %"strptr.3" = getelementptr inbounds [23 x i8], [23 x i8]* @".jk_str.3", i32 0, i32 0
  call void @"report"(i8* %"strptr.3")
  br label %"merge"
merge:
  %"strptr.4" = getelementptr inbounds [12 x i8], [12 x i8]* @".jk_str.4", i32 0, i32 0
  %"calltmp.1" = call i1 @"scan"(i8* %"strptr.4")
  br i1 %"calltmp.1", label %"then.1", label %"else.1"
then.1:
  %"strptr.5" = getelementptr inbounds [26 x i8], [26 x i8]* @".jk_str.5", i32 0, i32 0
  call void @"report"(i8* %"strptr.5")
  br label %"merge.1"
else.1:
  %"strptr.6" = getelementptr inbounds [13 x i8], [13 x i8]* @".jk_str.6", i32 0, i32 0
  call void @"report"(i8* %"strptr.6")
  br label %"merge.1"
merge.1:
  %"strptr.7" = getelementptr inbounds [14 x i8], [14 x i8]* @".jk_str.7", i32 0, i32 0
  call void @"report"(i8* %"strptr.7")
  ret void
}

@".jk_str.0" = internal constant [14 x i8] c"Starting scan\00"
@".jk_str.1" = internal constant [12 x i8] c"svchost.exe\00"
@".jk_str.2" = internal constant [21 x i8] c"svchost.exe: RUNNING\00"
@".jk_str.3" = internal constant [23 x i8] c"svchost.exe: not found\00"
@".jk_str.4" = internal constant [12 x i8] c"malware.exe\00"
@".jk_str.5" = internal constant [26 x i8] c"ALERT: malware.exe found!\00"
@".jk_str.6" = internal constant [13 x i8] c"System clean\00"
@".jk_str.7" = internal constant [14 x i8] c"Scan complete\00"