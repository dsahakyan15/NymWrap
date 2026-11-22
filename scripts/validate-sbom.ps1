#Requires -Version 7.0
param([Parameter(Mandatory=$true)][string]$Path)
$ErrorActionPreference='Stop'
$schemaRoot=Join-Path (Split-Path -Parent $PSScriptRoot) 'target/tools/cyclonedx-1.6'
New-Item -ItemType Directory -Path $schemaRoot -Force | Out-Null
function Read-PinnedSchema([string]$Name,[string]$Sha256) {
    $cached=Join-Path $schemaRoot $Name
    if (!(Test-Path -LiteralPath $cached)) {
        $temporary=$cached+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
        try {
            Invoke-WebRequest ('https://raw.githubusercontent.com/CycloneDX/specification/55343ba19dee1785acf1ce9191540d5fd7b590db/schema/'+$Name) -OutFile $temporary
            if ((Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash -ne $Sha256) { throw 'schema_hash_mismatch' }
            Move-Item -LiteralPath $temporary -Destination $cached -Force
        } finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force } }
    }
    if ((Get-FileHash -LiteralPath $cached -Algorithm SHA256).Hash -ne $Sha256) { throw 'schema_hash_mismatch' }
    return Get-Content -LiteralPath $cached -Raw | ConvertFrom-Json -AsHashtable -Depth 100
}
$bom=Read-PinnedSchema 'bom-1.6.schema.json' '3e92dddbc30cf7f6a02b80f0942b1a4cfd4fb1c26f1dfc4310afa9d613cafb93'
$spdx=Read-PinnedSchema 'spdx.schema.json' 'baa9d3bd1ed57b6751b0887edead6b5063ff53ff7429cf85d476c6c94af0166e'
$jsf=Read-PinnedSchema 'jsf-0.82.schema.json' '8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae'
# Inline the two pinned documents. Validation cannot fetch any unpinned reference.
[void]$spdx.Remove('$id');[void]$jsf.Remove('$id')
function Close-References($Node,[bool]$JsfScope) {
    if ($Node -is [System.Collections.IDictionary]) {
        if ($Node.Contains('$ref')) {
            $reference=[string]$Node['$ref']
            if ($JsfScope -and $reference.StartsWith('#/')) { $Node['$ref']='#/definitions/nymwrap-jsf'+$reference.Substring(1) }
            elseif ($reference -eq 'spdx.schema.json') { $Node['$ref']='#/definitions/nymwrap-spdx' }
            elseif ($reference -eq 'jsf-0.82.schema.json#/definitions/signature') { $Node['$ref']='#/definitions/nymwrap-jsf/definitions/signature' }
            elseif (!$reference.StartsWith('#/')) { throw 'unexpected_external_schema_reference' }
        }
        foreach ($value in @($Node.Values)) { Close-References $value $JsfScope }
    } elseif ($Node -is [System.Collections.IList]) { foreach ($value in $Node) { Close-References $value $JsfScope } }
}
Close-References $bom $false
Close-References $jsf $true
$bom.definitions['nymwrap-spdx']=$spdx
$bom.definitions['nymwrap-jsf']=$jsf
$schema=ConvertTo-Json -InputObject $bom -Depth 100 -Compress
if (!(Test-Json -Json (Get-Content -LiteralPath $Path -Raw) -Schema $schema -ErrorAction Stop)) { throw 'invalid_sbom' }
Write-Output 'CycloneDX 1.6 schema: valid'
