# 编译整个项目:src/main/java 下的所有 .java -> build/classes,
# 再把 classes 目录和 src/main/resources 一起打成 dist/cipherchat.jar。
# 每次都会先清空 build/classes,保证是干净构建,不会残留旧版本的 class。
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$sourceRoot = Join-Path $projectRoot 'src\main\java'
$resourceRoot = Join-Path $projectRoot 'src\main\resources'
$classesDir = Join-Path $projectRoot 'build\classes'
$distDir = Join-Path $projectRoot 'dist'

New-Item -ItemType Directory -Force -Path $classesDir, $distDir | Out-Null
Get-ChildItem -LiteralPath $classesDir -Force | Remove-Item -Recurse -Force

$sources = Get-ChildItem -LiteralPath $sourceRoot -Recurse -Filter '*.java' | Select-Object -ExpandProperty FullName
& javac -encoding UTF-8 -d $classesDir $sources
if ($LASTEXITCODE -ne 0) { throw 'Java compilation failed.' }

Get-ChildItem -LiteralPath $resourceRoot -Force | Copy-Item -Destination $classesDir -Recurse -Force
& jar --create --file (Join-Path $distDir 'cipherchat.jar') -C $classesDir .
if ($LASTEXITCODE -ne 0) { throw 'JAR packaging failed.' }

Write-Host "Build complete: $(Join-Path $distDir 'cipherchat.jar')"
