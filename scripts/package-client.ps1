# 用 jpackage 把客户端打包成自带 JRE 的免安装应用,输出到 dist/CipherChat-Updated。
# 注意:这里只打包客户端;服务端仍需目标机器装有 JDK 21。
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$distDir = Join-Path $projectRoot 'dist'
$jar = Join-Path $distDir 'cipherchat.jar'
$appName = 'CipherChat-Updated'
$appDir = Join-Path $distDir $appName
$packageInput = Join-Path $projectRoot 'build\package-input'

& (Join-Path $PSScriptRoot 'build.ps1')

if (Test-Path -LiteralPath $packageInput) {
    [System.IO.Directory]::Delete($packageInput, $true)
}
New-Item -ItemType Directory -Force -Path $packageInput | Out-Null
Copy-Item -LiteralPath $jar -Destination (Join-Path $packageInput 'cipherchat.jar') -Force

# jpackage 要求目标目录不存在,重复打包前先清掉旧版本。
# 注意:jpackage 生成的启动器 exe 带只读属性,直接递归删除会报"拒绝访问",
# 所以先统一清掉只读位再删。
if (Test-Path -LiteralPath $appDir) {
    Get-ChildItem -LiteralPath $appDir -Recurse -Force -File | ForEach-Object { $_.IsReadOnly = $false }
    [System.IO.Directory]::Delete($appDir, $true)
}

& jpackage `
    --type app-image `
    --name $appName `
    --input $packageInput `
    --main-jar 'cipherchat.jar' `
    --main-class 'cipherchat.client.CipherChatClient' `
    --dest $distDir `
    --description 'CipherChat encrypted desktop client' `
    --vendor 'CipherChat Course Project' `
    --java-options '-Dfile.encoding=UTF-8'

if ($LASTEXITCODE -ne 0) { throw 'Client packaging failed.' }
Write-Host "Client ready: $(Join-Path $appDir "$appName.exe")"
