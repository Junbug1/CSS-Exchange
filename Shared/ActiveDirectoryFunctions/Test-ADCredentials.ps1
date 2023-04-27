# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Invoke-CatchActionError.ps1

function Test-ADCredentials {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credentials,

        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $credentialsValid = $false
        try {
            Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop
        } catch {
            Write-Verbose "Failed to load System.DirectoryServices.Protocols"
            Invoke-CatchActionError $CatchActionFunction
        }
    }
    process {
        $domain = $Credentials.GetNetworkCredential().Domain
        if ([System.String]::IsNullOrEmpty($domain)) {
            Write-Verbose "Domain is empty which could be an indicator that UPN was passed instead of domain\username"
            $domain = ($Credentials.GetNetworkCredential().UserName).Split("@")
            if ($domain.Count -eq 2) {
                Write-Verbose "Domain was extracted from UPN"
                $domain = $domain[-1]
            } else {
                Write-Verbose "Failed to extract domain from UPN - seems that username was passed without domain and so cannot be validated"
                $domain = $null
            }
        }

        if (-not([System.String]::IsNullOrEmpty($domain))) {
            $ldapDirectoryIdentifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($domain)
            $ldapConnection = New-Object -TypeName System.DirectoryServices.Protocols.LdapConnection($ldapDirectoryIdentifier, $Credentials, [DirectoryServices.Protocols.AuthType]::Kerberos)
            $ldapConnection.SessionOptions.Signing = $true
            $ldapConnection.SessionOptions.Sealing = $true
            try {
                $ldapConnection.Bind()
                Write-Verbose "Connection succeeded with credentials"
                $credentialsValid = $true
            } catch {
                Write-Verbose "Failed to authenticate with credentials"
                Invoke-CatchActionError $CatchActionFunction
            }
        }
    }
    end {
        if ($null -ne $ldapConnection) {
            $ldapConnection.Dispose()
        }
        return $credentialsValid
    }
}
