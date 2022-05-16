﻿# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-WmiObjectHandler.ps1
Function Get-WmiObjectCriticalHandler {
    [CmdletBinding()]
    param(
        [string]
        $ComputerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $true)]
        [string]
        $Class,

        [string]
        $Filter,

        [string]
        $Namespace,

        [scriptblock]
        $CatchActionFunction
    )
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $params = @{
        ComputerName        = $ComputerName
        Class               = $Class
        Filter              = $Filter
        Namespace           = $Namespace
        CatchActionFunction = $CatchActionFunction
    }


    $wmi = Get-WmiObjectHandler @params

    if ($null -eq $wmi) {
        # Check for common issues that have been seen. If common issue, the do a Write-Error, custom message, then exit to maintain readability.

        # Grab the English version of hte message and/or the error code. Could get a different error code if service is not disabled.
        if ($Error[0].Exception.Message -like "The service cannot be started, either because it is disabled or because it has no enabled devices associated with it. *" -or
            $Error[0].Exception.ErrorCode -eq 0x80070422) {
            Write-Verbose "winmgmt service is disabled or not working."
            Write-Error $Error[0]
            Write-Warning "The 'winmgmt' service appears to not be working correctly. Please make sure it is set to Automatic and in a running state. This script will fail unless this is working correctly."
            exit
        }

        throw "Failed to get critical information. Stopping the script. InnerException: $($Error[0])"
    }

    return $wmi
}
