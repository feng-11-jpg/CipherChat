# 客户端启动器(根目录的“启动客户端.cmd”实际调用的就是它)。流程:
#   1. jar 不存在就先调用 build.ps1 构建;
#   2. 探测本机 5050 端口,判断是否已经有服务端在跑;
#   3. 没有就在后台静默起一个服务端,工作目录固定为项目根,数据才会落在 data/;
#   4. 优先打开打包好的 CipherChat-Updated.exe,否则退回 javaw 直接运行 jar。
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$jar = Join-Path $projectRoot 'dist\cipherchat.jar'
$clientExe = Join-Path $projectRoot 'dist\CipherChat-Updated\CipherChat-Updated.exe'

if (-not (Test-Path -LiteralPath $jar)) {
    & (Join-Path $PSScriptRoot 'build.ps1')
}

function Test-LocalServer {
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $connect = $client.BeginConnect('127.0.0.1', 5050, $null, $null)
        if (-not $connect.AsyncWaitHandle.WaitOne(300)) { return $false }
        $client.EndConnect($connect)
        return $true
    } catch {
        return $false
    } finally {
        $client.Dispose()
    }
}

if (-not (Test-LocalServer)) {
    $java = Get-Command java -ErrorAction Stop
    $arguments = "-cp `"$jar`" cipherchat.server.ChatServer 5050"
    $server = Start-Process -FilePath $java.Source -ArgumentList $arguments `
        -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru

    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while ([DateTime]::UtcNow -lt $deadline -and -not (Test-LocalServer)) {
        if ($server.HasExited) {
            throw '本机服务器启动失败。请检查 Java 安装，或运行“启动服务器.cmd”查看错误。'
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not (Test-LocalServer)) {
        throw '等待本机服务器启动超时。请运行“启动服务器.cmd”查看错误。'
    }
}

if (Test-Path -LiteralPath $clientExe) {
    Start-Process -FilePath $clientExe -WorkingDirectory $projectRoot
} else {
    $javaw = Get-Command javaw -ErrorAction Stop
    $arguments = "-cp `"$jar`" cipherchat.client.CipherChatClient"
    Start-Process -FilePath $javaw.Source -ArgumentList $arguments -WorkingDirectory $projectRoot
}
