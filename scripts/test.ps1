# 冒烟测试:在 5051 端口起一个临时服务端(状态文件写在系统临时目录,不碰 data/),
# 依次验证注册、加好友、加密消息转发与解密,结束后关闭服务端并清理临时数据。
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
& (Join-Path $PSScriptRoot 'build.ps1')

$testClasses = Join-Path $projectRoot 'build\test-classes'
New-Item -ItemType Directory -Force -Path $testClasses | Out-Null
Get-ChildItem -LiteralPath $testClasses -Force | Remove-Item -Recurse -Force

$testSources = Get-ChildItem -LiteralPath (Join-Path $projectRoot 'src\test\java') -Recurse -Filter '*.java' | Select-Object -ExpandProperty FullName
$jar = Join-Path $projectRoot 'dist\cipherchat.jar'
& javac -encoding UTF-8 -cp $jar -d $testClasses $testSources
if ($LASTEXITCODE -ne 0) { throw 'Test compilation failed.' }

$testRuntime = Join-Path ([System.IO.Path]::GetTempPath()) ("cipherchat-test-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $testRuntime | Out-Null
$server = Start-Process -FilePath 'java' -ArgumentList '-cp', $jar, 'cipherchat.server.ChatServer', '5051' -WorkingDirectory $testRuntime -WindowStyle Hidden -PassThru
try {
    Start-Sleep -Milliseconds 800
    & java -cp "$jar;$testClasses" cipherchat.SmokeTest
    if ($LASTEXITCODE -ne 0) { throw 'Smoke test failed.' }
} finally {
    if (-not $server.HasExited) { Stop-Process -Id $server.Id -Force }
    $resolvedTemp = [System.IO.Path]::GetFullPath($testRuntime)
    $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    if ($resolvedTemp.StartsWith($tempRoot) -and (Split-Path -Leaf $resolvedTemp).StartsWith('cipherchat-test-')) {
        Remove-Item -LiteralPath $resolvedTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
