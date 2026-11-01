param(
    [ValidateSet('aarch64-linux-android','armv7-linux-androideabi','x86_64-linux-android')]
    [string[]]$Targets = @('aarch64-linux-android','armv7-linux-androideabi'),
    [ValidateSet('debug','release')][string]$Configuration = 'release'
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$sdk = $env:ANDROID_SDK_ROOT
if (-not $sdk) { $sdk = $env:ANDROID_HOME }
if (-not $sdk) { $sdk = Join-Path $env:LOCALAPPDATA 'Android\Sdk' }
$ndk = Get-ChildItem -LiteralPath (Join-Path $sdk 'ndk') -Directory |
    Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
if (-not $ndk) { throw 'Install the Android NDK or set ANDROID_SDK_ROOT.' }
$ndkBin = Join-Path $ndk.FullName 'toolchains\llvm\prebuilt\windows-x86_64\bin'
$env:PATH = (Join-Path $env:USERPROFILE '.cargo\bin') + ';' + $env:PATH

# Optional LLVM-MinGW host tools for Windows without Visual Studio Build Tools.
$llvm = Get-ChildItem -Path (Join-Path $env:LOCALAPPDATA 'tgws-build-tools\llvm-mingw-*-ucrt-x86_64\bin') -Directory -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($llvm) {
    if (-not $env:RUSTUP_TOOLCHAIN) { $env:RUSTUP_TOOLCHAIN = 'stable-x86_64-pc-windows-gnu' }
    $env:PATH = $llvm.FullName + ';' + $env:PATH
    $env:CC_x86_64_pc_windows_gnu = Join-Path $llvm.FullName 'x86_64-w64-mingw32-clang.exe'
    $env:AR_x86_64_pc_windows_gnu = Join-Path $llvm.FullName 'llvm-ar.exe'
    $sysroot = (& rustc --print sysroot).Trim()
    $env:LIBRARY_PATH = Join-Path $sysroot 'lib\rustlib\x86_64-pc-windows-gnu\lib\self-contained'
}
$abis = @{'aarch64-linux-android'='arm64-v8a';'armv7-linux-androideabi'='armeabi-v7a';'x86_64-linux-android'='x86_64'}
$compilers = @{'aarch64-linux-android'='aarch64-linux-android24-clang.cmd';'armv7-linux-androideabi'='armv7a-linux-androideabi21-clang.cmd';'x86_64-linux-android'='x86_64-linux-android24-clang.cmd'}
Push-Location $projectRoot
try {
    foreach ($target in $Targets) {
        $underscored = $target.Replace('-','_')
        $compiler = Join-Path $ndkBin $compilers[$target]
        [Environment]::SetEnvironmentVariable("CC_$underscored",$compiler,'Process')
        [Environment]::SetEnvironmentVariable("AR_$underscored",(Join-Path $ndkBin 'llvm-ar.exe'),'Process')
        [Environment]::SetEnvironmentVariable("CARGO_TARGET_$($underscored.ToUpper())_LINKER",$compiler,'Process')
        $arguments = @('build','--locked','--target',$target)
        if ($Configuration -eq 'release') { $arguments += '--release' }
        & cargo @arguments
        if ($LASTEXITCODE -ne 0) { throw "Native build failed: $target" }
        $destination = Join-Path $projectRoot "app\src\main\jniLibs\$($abis[$target])"
        New-Item -ItemType Directory -Path $destination -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $projectRoot "target\$target\$Configuration\libtgwsproxy.so") -Destination $destination
    }
} finally { Pop-Location }
