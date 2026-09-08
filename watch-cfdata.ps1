param(
    [Parameter(Mandatory = $true)]
    [string]$AppDir,
    [string]$ExtraArgs = ''
)

$ErrorActionPreference = 'Stop'
$defaultPort = 13336
$sourceExtensions = @('.go', '.html', '.js', '.css', '.png')
$child = $null

function Get-SourceSnapshot {
    $items = Get-ChildItem -LiteralPath $AppDir -Recurse -File | Where-Object {
        $sourceExtensions -contains $_.Extension.ToLowerInvariant()
    }
    $parts = foreach ($item in $items) {
        '{0}|{1}|{2}' -f $item.FullName, $item.Length, $item.LastWriteTimeUtc.Ticks
    }
    return ($parts | Sort-Object) -join "`n"
}

function Stop-ChildTree {
    if ($null -eq $script:child -or $script:child.HasExited) {
        $script:child = $null
        return
    }
    Write-Host '[CFData] stopping old process...'
    & taskkill.exe /PID $script:child.Id /T /F *> $null
    $script:child = $null
}

function Start-Child {
    $arguments = "run . -host 127.0.0.1 -port $defaultPort"
    if (-not [string]::IsNullOrWhiteSpace($ExtraArgs)) {
        $arguments += " $ExtraArgs"
    }
    Write-Host "[CFData] starting on http://127.0.0.1:$defaultPort (source watch enabled)"
    $script:child = Start-Process -FilePath 'go.exe' -ArgumentList $arguments -WorkingDirectory $AppDir -NoNewWindow -PassThru
}

try {
    $snapshot = Get-SourceSnapshot
    Start-Child
    while ($true) {
        Start-Sleep -Milliseconds 700
        $nextSnapshot = Get-SourceSnapshot
        if ($nextSnapshot -ne $snapshot) {
            $snapshot = $nextSnapshot
            Stop-ChildTree
            Start-Sleep -Milliseconds 250
            Start-Child
        }
    }
}
finally {
    Stop-ChildTree
}
