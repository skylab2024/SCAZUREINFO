<#
 This DSC script is used for hardening cryptographic protocols on Andersen Windows servers.
 Running this script against Andersen Windows servers helps protect from vulnerability attacks.  
 This script enables Protocols TLS 1.1 and TLS 1.2 for various older applications.
 For this script to work you may need to enable local policy to utilize FIPS complaint algorythms for encryption.
 Steps to enable the FIPS setting:
 1.In Control Panel, click Administrative Tools, and then double-click Local Security Policy.
 2.In Local Security Settings, expand Local Policies, and then click Security Options.
 3.Under Policy in the right pane, double-click System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing, and then click Enabled.
    a.  You may need to restart or kill wmiprvse.exe process before running this DSC script.
This script also disables SMB-1.
This script also disables the Firewall settings at the server level.
 #> 

#Ciphers, Hashes and Protocols to Disable/Enable
  
  
  $disableCiphers=@('DES 56/56','NULL','RC2 128/128','RC2 40/128','RC2 56/128','RC4 64/128','Triple DES 168/168') 

  $disableCiphers1=@('RC4 40/128','RC4 56/128','RC4 128/128') 
 
  $enableCiphers=@('AES 128/128','AES 256/256')
  
  $enableHashes=@("SHA","SHA256","SHA384","SHA512") 
 
  $disableProtocols=@("SSL 2.0","SSL 3.0","Multi-Protocol Unified Hello","PCT 1.0","TLS 1.0")  
 
  $enableProtocols=@("TLS 1.1","TLS 1.2") 
 
 Configuration BaseSvrConfigEnabledTLS1_1_1_2v1_5 { 

#Import PSDesiredStateConfiguration Module to be used with the psRegistry resource for script usage
#Import xPSDesiredStateConfiguration Module to be used with the xRegistry resource for script usage

Import-DscResource -Modulename PSDesiredStateConfiguration
Import-DscResource -ModuleName xPSDesiredStateConfiguration 
 
#begin- BaseSvrConfigEnabledTLS1_1_1_2v1_5
 
#begin- Ciphers 
 foreach ($cipher in $disableCiphers) { 
     xRegistry $cipher { 
 
         Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher" 
         ValueName = "Enabled" 
         Ensure    = "Present" 
         Force     = $True 
         ValueData = 0 
         ValueType = "Dword" 
     } 
 } 
 
  foreach ($cipher in $enableCiphers) { 
 
     xRegistry $cipher { 
 
         Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher" 
         ValueName = "Enabled" 
         Ensure    = "Present" 
         Force     = $True 
         Hex       = $True 
         ValueData = "0xFFFFFFFF" 
         ValueType = "Dword" 
     } 
 } 
#end- Ciphers 

#begin - $Ciphers1
foreach ($cipher1 in $disableCiphers1) { 
    Registry $cipher1 { 

        Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher1" 
        ValueName = "Enabled" 
        Ensure    = "Present" 
        Force     = $True 
        Hex       = $True
        ValueData = 0x0
        ValueType = "String" 
    } 
} 
#end - Ciphers1
 
#begin- Hashes 
 foreach ($hash in $enableHashes){ 
 
       Registry $hash { 
 
           Key              = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$hash" 
           ValueName        = "Enabled" 
           Ensure           = "Present" 
           Force            = $True 
           Hex              = $True 
           ValueData        = "0xFFFFFFFF" 
           ValueType        = "Dword" 
       } #registry resource 

 } #foreach service 
 
       #Disable MD5 hashing algorithm 
       Registry MD5 { 
 
           Key              = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5" 
           ValueName        = "Enabled" 
           Ensure           = "Present" 
           Force            = $True 
           ValueData        = "0" 
       } 
#end- Hashes 
  
#begin Disable SSL 2,3 and TLS 1.0 
   foreach ($protocol in $disableProtocols) { 
 
         Registry "Client-Enabled$protocol" { 
 
             Key         = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client" 
             ValueName   = "Enabled" 
             Ensure      = "Present" 
             Force       = $True 
             ValueType   = "Dword" 
             ValueData   = "0" 
         } 
 
         Registry "Client-DBD$protocol" { 
 
             Key         = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client" 
             ValueName   = "DisabledByDefault" 
             Ensure      = "Present" 
             Force       = $True 
             Hex         = $True 
             ValueType   = "Dword" 
             ValueData   = "0x00000001" 
         } 
 
         Registry "Server-Enabled$protocol" { 
 
             Key        = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server" 
             ValueName  = "Enabled" 
             Ensure     = "Present" 
             Force      = $True 
             ValueData  = "0" 
             ValueType  = "Dword" 
         } 
 
         Registry "Server-DBD$protocol" { 
 
             Key        = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server" 
             ValueName  = "DisabledByDefault" 
             Ensure     = "Present" 
             Force      = $True 
             Hex        = $True 
             ValueData  = "0x00000001" 
             ValueType  = "Dword" 
         } #registry resource 

 } #foreach service 
#end- Disable SSL 2,3 and TLS 1.0 
 
#begin- Enable TLS 1.1 and 1.2 
   foreach ($protocol in $enableProtocols) { 
 
         Registry "Client-Enabled$protocol" { 
 
             Key         = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client" 
             ValueName   = "Enabled" 
             Ensure      = "Present" 
             Hex         = $True 
             Force       = $True 
             ValueData   = "0xFFFFFFFF" 
             ValueType   = "Dword" 
         } 
 
         Registry "Client-DBD$protocol" { 
 
             Key         = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client" 
             ValueName   = "DisabledByDefault" 
             Ensure      = "Present" 
             Force       = $True 
             ValueData   = "0" 
         } 
 
         Registry "Server-Enabled$protocol" { 
 
             Key        = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server" 
             ValueName  = "Enabled" 
             Ensure     = "Present" 
             Force      = $True 
             Hex        = $True 
             ValueData  = "0xFFFFFFFF" 
             ValueType  = "Dword" 
         } 
 
         Registry "Server-DBD$protocol" { 
 
             Key        = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server" 
             ValueName  = "DisabledByDefault" 
             Ensure     = "Present" 
             Force      = $True 
             ValueData  = "0" 
         } 
 
 } 
#end- Enable TLS 1.1 and 1.2 

#begin- Disable SMB1
     WindowsFeature SMB1 
       {
           Ensure = 'Absent' 
           Name = 'FS-SMB1' 
  
       } 
   
         #Service Link-LayerTopologyDiscoveryMapper
            #{
               #Name = 'lltdsvc'
               #State = 'Stopped'
               #StartupType = 'Disabled'
            #}
#end- Disable SMB1

#begin- Firewall
     Script DisableFirewall 
        {
            GetScript = {
            @{
                GetScript = $GetScript
                SetScript = $SetScript
                TestScript = $TestScript
                Result = -not('True' -in (Get-NetFirewallProfile -All).Enabled)
            }
        }

        SetScript = {
            Set-NetFirewallProfile -All -Enabled False -Verbose
        }
 
        TestScript = {
            $Status = -not('True' -in (Get-NetFirewallProfile -All).Enabled)
            $Status -eq $True
        }
    }
#end- Firewall
#end- BaseSvrConfigEnabledTLS1_1_1_2v1_5
 }
BaseSvrConfigEnabledTLS1_1_1_2v1_5