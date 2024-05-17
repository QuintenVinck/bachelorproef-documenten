# Define the list of computers
$computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

# Initialize an array to store collected information
$collectedInformation = @()

$credential = Get-Credential -Message "Enter credentials for $computer"

# Loop through each computer
foreach ($index in 0..($computers.Count - 1)) {

    $computer = $computers[$index]

    Write-Host "Connecting to $computer..."
    # Prompt for credentials for each computer

    # Attempt to establish a remote PowerShell session
    try {
        $session = New-PSSession -ComputerName $computer -Credential $credential -ErrorAction Stop

        $domain = Invoke-Command -Session $session -ScriptBlock {
            Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select-Object -ExpandProperty Domain
        }

        $listeningPorts = Invoke-Command -Session $session -ScriptBlock {
            Get-NetTcpConnection |
                Where-Object { $_.State -eq "Listen" } |
                Select-Object LocalAddress, LocalPort, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} |
                ConvertTo-Json -Depth 3
        }

        $establishedConnections = Invoke-Command -Session $session -ScriptBlock {
            Get-NetTCPConnection -State Established |
                Select-Object -Property LocalAddress, LocalPort, @{name='RemoteHostName';expression={(Resolve-DnsName $_.RemoteAddress -ErrorAction Stop).NameHost}}, RemoteAddress, RemotePort, State, @{name='ProcessName';expression={(Get-Process -Id $_.OwningProcess -ErrorAction Stop).Path}}, OffloadState, CreationTime |
                Group-Object -Property LocalAddress, LocalPort, RemoteAddress, RemotePort |
                ForEach-Object {$_.Group[0]} |
                Select-Object -Property LocalPort, RemoteHostName, RemotePort, ProcessName, CreationTime
        }

        $establishedConnections = $establishedConnections | Select-Object -Property LocalPort, RemoteHostName, RemotePort, ProcessName, CreationTime

        $ipConfigInfo = Invoke-Command -Session $session -ScriptBlock {
            $output = ipconfig | Select-String -Pattern "IPv4 Address", "Subnet Mask", "Default Gateway", "DNS Suffix", "Link-local IPv6 Address" | ForEach-Object {$_.Line}
            $ipAddress = ($output | Select-String -Pattern "\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").Matches.Value[0]
            $subnetMask = ($output | Select-String -Pattern "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").Matches.Value[1]
            $defaultGateway = ($output | Select-String -Pattern "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").Matches.Value[2]
            $dnsSuffix = ($output | Select-String -Pattern "DNS Suffix").Line.Replace("Connection-specific DNS Suffix  . : ","").Trim()

            [PSCustomObject]@{
                IPAddress     = $ipAddress
                SubnetMask    = $subnetMask
                DefaultGateway = $defaultGateway
                DnsSuffix     = $dnsSuffix
            }

        }

        $ipConfigInfo = $ipConfigInfo | Select-Object IPAddress, SubnetMask, DefaultGateway, DnsSuffix

        $computerInfo = Invoke-Command -Session $session -ScriptBlock {
            $computerInfo = Get-ComputerInfo | ForEach-Object {
                "$($_.WindowsBuildLabEx)",
                "$($_.WindowsCurrentVersion)",
                "$($_.WindowsProductName)",
                "$($_.WindowsVersion)",
                "$($_.OsName)",
                "$($_.OsVersion)"
            }
            [PSCustomObject]@{
                WindowsBuildLabEx   = $computerInfo[0]
                WindowsCurrentVersion = $computerInfo[1]
                WindowsVersion      = $computerInfo[3]
                OsName               = $computerInfo[4]
                OsVersion            = $computerInfo[5]
            }
        }

        $computerInfo = $computerInfo | Select-Object WindowsBuildLabEx, WindowsCurrentVersion, WindowsVersion, OsName, OsVersion

        $firewallProfiles = Invoke-Command -Session $session -ScriptBlock {
            $domainProfile = Get-NetFirewallProfile -Profile Domain | Select-Object -ExpandProperty Enabled
            $privateProfile = Get-NetFirewallProfile -Profile Private | Select-Object -ExpandProperty Enabled
            $publicProfile = Get-NetFirewallProfile -Profile Public | Select-Object -ExpandProperty Enabled

            $WinDefDomainEnabled = if ($domainProfile -eq 1) { $true } else { $false }
            $WinDefPrivateEnabled = if ($privateProfile -eq 1) { $true } else { $false }
            $WinDefPublicEnabled = if ($publicProfile -eq 1) { $true } else { $false }

            [PSCustomObject]@{
                DomainProfile  = $WinDefDomainEnabled
                PrivateProfile = $WinDefPrivateEnabled
                PublicProfile  = $WinDefPublicEnabled
            }
        }

        $roleInfo = Invoke-Command -Session $session -ScriptBlock {

            try {
            $isDomainController = (Get-WmiObject Win32_ComputerSystem).DomainRole -eq 5
    
            $isIISInstalled = @(Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Installed)
            $isIISInstalled = if ($isIISInstalled) { $true } else { $false }

            $isDNSInstalled = @(Get-WindowsFeature -Name DNS -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Installed)
            $isDNSInstalled = if ($isDNSInstalled) { $true } else { $false }

            $isDHCPInstalled = @(Get-WindowsFeature -Name DHCP -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Installed)
            $isDHCPInstalled = if ($isDHCPInstalled) { $true } else { $false }

            $isFileServerInstalled = @(Get-WindowsFeature -Name FS-FileServer -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Installed)
            $isFileServerInstalled = if ($isFileServerInstalled) { $true } else { $false }

            $isADCSInstalled = @(Get-WindowsFeature -Name ADCS-Cert-Authority -ErrorAction SilentlyContinue)
            $isADCSInstalled = if ($isADCSInstalled) { $true } else { $false }

            $isRDSInstalled = @(Get-WindowsFeature -Name Remote-Desktop-Services)
            $isRDSInstalled = if ($isRDSInstalled) { $true } else { $false }
            } catch {
            #Silent error
            }

            [PSCustomObject]@{
                isDomainController = $isDomainController
                isIISInstalled = $isIISInstalled
                isDNSInstalled = $isDNSInstalled
                isDHCPInstalled = $isDHCPInstalled
                isFileServerInstalled = $isFileServerInstalled
                isADCSInstalled = $isADCSInstalled
                isRDSInstalled = $isRDSInstalled
            }
        }

        $infoDC = Invoke-Command -Session $session -ScriptBlock {
            try {
            $dcInfo = Get-ADDomainController -ErrorAction SilentlyContinue
            } catch {
            }
            [PSCustomObject]@{
                dcInfo     = $dcInfo
            }
        }

        $infoIIS = Invoke-Command -Session $session -ScriptBlock {
            try {
            $IISInfo = Get-Website -ErrorAction SilentlyContinue | Select-Object name, id, serverAutoStart, state, binding, limits, logFile, traceFailedRequestsLogging, hsts, applicationDefaults, virtualDirectoryDefaults, ftpServer, Collection, applicationPool, enabledProtocols, physicalPath, userName, password, Attributes, ChildElements, ElementTagName, Methods, Schema
            $IISInfo2 = Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue | Select-Object name, queueLength, autoStart, enable32BitAppOnWin64, managedRuntimeVersion, managedRuntimeLoader, enableConfigurationOverride, managedPipelineMode, CLRConfigFile, passAnonymousToken, startMode, state, applicationPoolSid, processModel,recycling, failure, cpu, environmentVariables, workerProcesses, ItemXPath, PSPath, PSParentPath, PSChildName, PSDrive.Name, PSProvider.Name, PSIsContainer, Attributes, ChildElements, ElementTagName, Methods, Schema
            } catch {
            }

            [PSCustomObject]@{
                iisInfo     = $IISInfo
                iisInfo2    = $IISInfo2
            }
        }

        $infoDNS = Invoke-Command -Session $session -ScriptBlock {

            try {
            $dnsSetting = Get-DnsServerSetting | Select-Object AllIPAddress, BuildNumber, ComputerName, EnableDnsSec, EnableIPv6, IsReadOnlyDC, ListeningIPAddress, MajorVersion, MinorVersion
            $dnsZone = Get-DnsServerZone | Select-Object DistinguishedName, IsAutoCreated, IsDsIntegrated, IsPaused, IsReadOnly, IsReverseLookupZone, IsShutdown, ZoneName, ZoneType, AllowedDcForNsRecordsAutoCreation, DirectoryPartitionName, DynamicUpdate, IgnorePolicies, IsSigned, IsWinsEnabled, Notify, NotifyServers, ReplicationScope, SecondaryServers, SecureSecondaries, ZoneFile
            $dnsCache = Get-DnsServerCache | Select-Object DistinguishedName, IsAutoCreated, IsDsIntegrated, IsPaused, IsReadOnly, IsReverseLookupZone, IsShutdown, ZoneName, ZoneType, EnablePollutionProtection, IgnorePolicies, LockingPercent, MaxKBSize, MaxNegativeTtl, MaxTtl, StoreEmptyAuthenticationResponse
            $dnsResponseRateLimit = Get-DnsServerResponseRateLimiting | Select-Object ErrorsPerSec, IPv4PrefixLength, IPv6PrefixLength, LeakRate, MaximumResponsesPerWindow, Mode, ResponsesPerSec, TruncateRate, WindowInSec
            $dnsResponseRateLimitException = Get-DnsServerResponseRateLimitingExceptionlist
            $dnsGlobalQueryBlockList = Get-DnsServerGlobalQueryBlockList | Select-Object Enable, List
            $dnsEdns = Get-DnsServerEdns | Select-Object CacheTimeout, EnableProbes, EnableReception
            $dnsForwarder = Get-DnsServerForwarder | Select-Object EnableReordering, IPAddress, ReorderedIPAddress, Timeout, UseRootHint
            #$dnsRootHint = Get-DnsServerRootHint | Select-Object NameServer, IPAddress

            $dnsScavenging = Get-DnsServerScavenging | Select-Object LastScavengeTime, NoRefreshInterval, RefreshInterval, ScavengingInterval, ScavengingState
            $dnsClientSubnet = Get-DnsServerClientSubnet
            } catch {
            }

            [PSCustomObject]@{
                #dnsServer = $dnsServer
                dnsSetting = $dnsSetting
                dnsZone = $dnsZone
                dnsCache = $dnsCache
                dnsResponseRateLimit = $dnsResponseRateLimit
                dnsResponseRateLimitException = $dnsResponseRateLimitException
                dnsGlobalQueryBlockList = $dnsGlobalQueryBlockList
                dnsEdns = $dnsEdns
                dnsForwarder = $dnsForwarder
                dnsScavenging = $dnsScavenging
                dnsClientSubnet = $dnsClientSubnet   
            }
        }

        $infoDhcp = Invoke-Command -Session $session -ScriptBlock {
            try {
            $dhcp1 = Get-DhcpServerSetting -ErrorAction SilentlyContinue | Select-Object ActivatePolicies, ConflictDetectionAttempts, DynamicBootp, IsAuthorized, IsDomainJoined, NapEnabled, NpsUnreachableAction, RestoreStatus
            $dhcp2 = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue | Select-Object ActivatePolicies, Delay, Description, EndRange, LeaseDuration, MaxBootpClients, Name, NapEnable, NapProfile, ScopeId, StartRange, State, SubnetMask, SuperscopeName, Type
            $dhcp3 = Get-DhcpServerv4ScopeStatistics -ErrorAction SilentlyContinue | Select-Object Free, InUse, Reserved, Pending, AddressesFree, AddressesFreeOnPartnerServer, AddressesFreeOnThisServer, AddressesInUse, AddressesInUseOnPartnerServer, AddressesInUseOnThisServer, PendingOffers, PercentageInUse, ReservedAddress, ScopeId, SuperscopeName
            } catch {
            }
            [PSCustomObject]@{
                dhcp1 = $dhcp1
                dhcp2 = $dhcp2
                dhcp3 = $dhcp3
            }
        }

        $infoFs = Invoke-Command -Session $session -ScriptBlock {
            try {
            $fileServer1 = Get-SmbShare -ErrorAction SilentlyContinue | Select-Object AvailabilityType, CachingMode, CATimeout, CompressData, ConcurrentUserLimit, ContinuouslyAvailable, CurrentUsers, Description, EncryptData, FolderEnumerationMode, IdentityRemoting, Infrastructure, LeasingMode, Name, Path, Scoped, ScopeName, SecurityDescriptor, ShadowCopy, ShareState, ShareType, SmbInstance, Special, Temporary, Volume
            $fileServer2 = Get-StorageFileServer -ErrorAction SilentlyContinue | Select-Object @{Name = "ObjectId"
                                                                                                Expression = { $_.ObjectId -replace '"', "'" }
                                                                                            }, PassThroughClass, PassThroughIds, PassThroughNamespace, PassThroughServer, UniqueId, FileSharingProtocols, FileSharingProtocolVersions, FriendlyName, HealthStatus, HostNames, OperationalStatus, OtherOperationalStatusDescription, SupportsContinuouslyAvailableFileShare, SupportsFileShareCreation
            $fileServer3 = Get-SmbServerConfiguration -ErrorAction SilentlyContinue | Select-Object AnnounceComment, AnnounceServer, AsynchronousCredits, AuditSmb1Access, AutoDisconnectTimeout, AutoShareServer, AutoShareWorkstation, CachedOpenLimit, DisableSmbEncryptionOnSecureConnection, DurableHandleV2TimeoutInSeconds, EnableAuthenticateUserSharing, EnableDownlevelTimewarp, EnableForcedLogoff, EnableLeasing, EnableMultiChannel, EnableOplocks, EnableSecuritySignature, EnableSMB1Protocol, EnableSMB2Protocol, EnableSMBQUIC, EnableStrictNameChecking, EncryptData, EncryptionCiphers, IrpStackSize, KeepAliveTime, MaxChannelPerSession, MaxMpxCount, MaxSessionPerConnection, MaxThreadsPerQueue, MaxWorkItems, NullSessionPipes, NullSessionShares, OplockBreakWait, PendingClientTimeoutInSeconds, RejectUnencryptedAccess, RequireSecuritySignature, RestrictNamedpipeAccessViaQuic, ServerHidden, Smb2CreditsMax, Smb2CreditsMin, SmbServerNameHardeningLevel, TreatHostAsStableStorage, ValidateAliasNotCircular, ValidateShareScope, ValidateShareScopeNotAliased, ValidateTargetName
            } catch {
            }

            [PSCustomObject]@{
                fileserver1 = $fileserver1
                fileserver2 = $fileserver2
                fileserver3 = $fileserver3
            }
        }

        $infoADCS = Invoke-Command -Session $session -ScriptBlock {

            try {
            $personal = Get-ChildItem -Path Cert:\\LocalMachine\\My\\* | Select-Object -Property Thumbprint, @{Name="Subject";Expression={$_.Subject.ToString().Replace('"',"'")}}
            $personal30 = Get-ChildItem -Path Cert:\LocalMachine\My\* -ExpiringInDays 30 | Select-Object -Property Thumbprint, @{Name="Subject";Expression={$_.Subject.ToString().Replace('"',"'")}}
            $personal0 =Get-ChildItem -Path Cert:\LocalMachine\My\* -ExpiringInDays 0 | Select-Object -Property Thumbprint, @{Name="Subject";Expression={$_.Subject.ToString().Replace('"',"'")}}
            $root30 = Get-ChildItem -Path Cert:\LocalMachine\Root -ExpiringInDays 30 | Select-Object -Property Thumbprint, @{Name="Subject";Expression={$_.Subject.ToString().Replace('"',"'")}}
            $root0 = Get-ChildItem -Path Cert:\LocalMachine\Root -ExpiringInDays 0 | Select-Object -Property Thumbprint, @{Name="Subject";Expression={$_.Subject.ToString().Replace('"',"'")}}
            } catch {
            }

            [PSCustomObject]@{
                'PersonalCerts' = $personal
                'PersonalCertsExpireIn30' = $personal30
                'PersonalCertsExpired' = $personal0
                'RootCertsExpireIn30' = $root30
                'RootCertsExpired' = $root0
            }
        }

        $date = Get-Date -Format "yyyy-MM-dd-HH_mm"

        # Add collected information to the array
        $collectedInformation = [Ordered]@{
            ComputerName            = $computer
           # SystemInfo              = $systemInfo
           # NetworkInfo             = $networkInfo
            date = $date
            ipconfigInfo = $ipConfigInfo
            Domain = $domain
            computerInfo = $computerInfo
            firewallProfiles = $firewallProfiles
            ListeningPorts          = ($listeningPorts | ConvertFrom-Json)
            EstablishedConnections  = $establishedConnections
            roleInfo = $roleInfo
            infoDC = $infoDC
            infoIIS = $infoIIS
            infoDNS = $infoDNS
            infoDhcp = $infoDhcp
            infoFs = $infoFs
            infoADCS = $infoADCS
            

                       
            # Add more sections as needed
        }

        $json = $collectedInformation | ConvertTo-Json -Depth 3 | % { [System.Text.RegularExpressions.Regex]::Unescape($_) }
        $json -replace '\\', '\\' | Out-File -FilePath "C:\Users\Walt\Documents\data\data_$($computer).json"

        # Close the remote PowerShell session
        Remove-PSSession -Session $session
        Write-Host "Successfully collected information from $computer."
    }
    catch {
        Write-Host "Failed to connect to $computer : $_"
    }
}

