# Submit a 2-file scan to the production TrustLedger API.
# Usage: ./scripts/submit-scan.ps1 -ApiKey "tl_live_..."

param(
  [Parameter(Mandatory = $true)]
  [string]$ApiKey,
  [string]$BaseUrl = "https://dashboard-psi-smoky-96.vercel.app",
  [string]$Repo = "novapay/payments-api"
)

$dir = Join-Path $PSScriptRoot "scan-payload-files"

$files = @(
  @{ path = "src/api/webhook_handler.py"; content = [string](Get-Content -Raw (Join-Path $dir "webhook_handler.py")) },
  @{ path = "src/utils/logger.ts";        content = [string](Get-Content -Raw (Join-Path $dir "logger.ts")) }
)

$commitSha = -join ((1..40) | ForEach-Object { "{0:x}" -f (Get-Random -Maximum 16) })

$body = @{
  repo       = $Repo
  pr_number  = 0
  commit_sha = $commitSha
  branch     = "main"
  files      = $files
} | ConvertTo-Json -Depth 6

# Org API keys (tl_live_...) authenticate via X-TrustLedger-Key, not Bearer
# (Bearer is reserved for Supabase session JWTs — see src/app/api/_middleware.ts)
$headers = @{
  "X-TrustLedger-Key" = $ApiKey
  "Content-Type"      = "application/json"
}

try {
  $response = Invoke-RestMethod -Uri "$BaseUrl/api/scans" -Method Post -Headers $headers -Body $body
  $response | ConvertTo-Json -Depth 6
} catch {
  $errResp = $_.Exception.Response
  if ($errResp) {
    $stream = $errResp.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($stream)
    Write-Host $reader.ReadToEnd()
  } else {
    throw
  }
}
