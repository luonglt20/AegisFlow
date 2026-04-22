Param()

$excludeDirs = @("node_modules", ".git")

# List of files to search and replace
Get-ChildItem -Path . -Recurse -File | Where-Object {
    $file = $_
    $skip = $false
    foreach ($ex in $excludeDirs) {
        if ($file.FullName -match "\\$ex\\") {
            $skip = $true
            break
        }
    }
    if ($skip) { return $false }

    $ext = $file.Extension
    if ($ext -match "\.(py|json|html|md|yml|yaml|sh|js)$" -or $file.Name -eq "Makefile" -or $file.Name -eq "Dockerfile") {
        return $true
    }
    return $false
} | ForEach-Object {
    $path = $_.FullName
    try {
        $content = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)
    } catch {
        return
    }
    $original = $content

    $content = $content -replace "localhost:3000", "localhost:53000"
    $content = $content -replace "3000:3000", "53000:53000"
    $content = $content -replace "EXPOSE 3000", "EXPOSE 53000"
    $content = $content -replace "`"@port`": `"3000`"", "`"@port`": `"53000`""
    $content = $content -replace "Node.js:3000", "Node.js:53000"
    $content = $content -replace "\|\| 3000", "|| 53000"

    $content = $content -replace "localhost:8080", "localhost:58080"
    $content = $content -replace "8080:80", "58080:80"
    $content = $content -replace "nginx:8080", "nginx:58080"

    if ($content -cne $original) {
        [System.IO.File]::WriteAllText($path, $content, [System.Text.Encoding]::UTF8)
        Write-Host "Updated $($_.Name)"
    }
}

Write-Host "Replaced all ports successfully."
