 $counters =
    @(`
    "\Processor(_Total)\% Processor Time" `
    ,"\Memory\Available MBytes" `
    ,"\Paging File(_Total)\% Usage" `
    ,"\LogicalDisk(*)\Avg. Disk Bytes/Read" `
    ,"\LogicalDisk(*)\Avg. Disk Bytes/Write" `
    ,"\LogicalDisk(*)\Avg. Disk sec/Read" `
    ,"\LogicalDisk(*)\Avg. Disk sec/Write" `
    ,"\LogicalDisk(*)\Disk Read Bytes/sec" `
    ,"\LogicalDisk(*)\Disk Write Bytes/sec" `
    ,"\LogicalDisk(*)\Disk Reads/sec" `
    ,"\LogicalDisk(*)\Disk Writes/sec"
    )
$variables = @{
    SampleInterval = 5
    Counter = $counters
    MaxSamples = 6
}
Get-Counter @Variables | Export-Counter -FileFormat csv -Path "counters.csv" -Force