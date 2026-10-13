# 前台启动服务端,监听 5050 端口。jar 缺失时先自动构建。
# 必须在项目根目录运行,否则状态文件会生成到别的 data/ 目录里。
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$jar = Join-Path $projectRoot 'dist\cipherchat.jar'
if (-not (Test-Path -LiteralPath $jar)) {
    & (Join-Path $PSScriptRoot 'build.ps1')
}
Set-Location $projectRoot
& java -cp $jar cipherchat.server.ChatServer 5050
