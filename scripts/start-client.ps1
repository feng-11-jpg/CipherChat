# 前台启动客户端(javaw,不额外占用命令行窗口)。jar 缺失时先自动构建。
# 默认连接本机 127.0.0.1:5050,服务器地址可以在客户端登录页修改。
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$jar = Join-Path $projectRoot 'dist\cipherchat.jar'
if (-not (Test-Path -LiteralPath $jar)) {
    & (Join-Path $PSScriptRoot 'build.ps1')
}
Set-Location $projectRoot
& javaw -cp $jar cipherchat.client.CipherChatClient
