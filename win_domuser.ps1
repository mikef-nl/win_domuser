#!powershell
# This file is part of Ansible
#
# Copyright 2014, Paul Durivage <paul.durivage@rackspace.com>
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

# WANT_JSON
# POWERSHELL_COMMON

########
Import-Module ActiveDirectory
$ADS_UF_PASSWD_CANT_CHANGE = 64
$ADS_UF_DONT_EXPIRE_PASSWD = 65536

$adsi = [ADSI]"WinNT://$env:COMPUTERNAME"

function Get-User($user) {
    Get-ADUser -Filter 'SamAccountName -like $user' -Properties *
    return
}

function Get-UserFlag($user, $flag) {
    switch ($flag)
    {
        64 {(Get-ADUser -Filter 'SamAccountName -like $user' -Properties *).CannotChangePassword}
        65536 {(Get-ADUser -Filter 'SamAccountName -like $user' -Properties *).PasswordNeverExpires}
    }
}

function Set-UserFlag($user, $flag) { 
    switch ($flag) 
    {
        64 {Set-ADUser $user -CannotChangePassword $true}
        65536 {Set-ADUser $user -PasswordNeverExpires $true}
    }
}

function Clear-UserFlag($user, $flag) {
    switch ($flag) 
    {
        64 {Set-ADUser $user -CannotChangePassword $false}
        65536 {Set-ADUser $user -PasswordNeverExpires $false}
    }
}

########

$params = Parse-Args $args;

$result = @{
    changed = $false
    msg = ""
};

$username = Get-AnsibleParam -obj $params -name "name" -type "str" -failifempty $true
$upn = Get-AnsibleParam -obj $params -name "upn" -type "str" -failifempty $true
$fullname = Get-AnsibleParam -obj $params -name "fullname" -type "str"
$description = Get-AnsibleParam -obj $params -name "description" -type "str"
$password = Get-AnsibleParam -obj $params -name "password" -type "str"
$state = Get-AnsibleParam -obj $params -name "state" -type "str" -default "present" -validateset "present","absent","query"
$ou = Get-AnsibleParam -obj $params -name "ou" -type "str"
$update_password = Get-AnsibleParam -obj $params -name "update_password" -type "str" -default "always" -validateset "always","on_create"
$password_expired = Get-AnsibleParam -obj $params -name "password_expired" -type "bool"
$password_never_expires = Get-AnsibleParam -obj $params -name "password_never_expires" -type "bool"
$user_cannot_change_password = Get-AnsibleParam -obj $params -name "user_cannot_change_password" -type "bool"
$account_enabled = Get-AnsibleParam -obj $params -name "account_enabled" -type "bool"
$account_locked = Get-AnsibleParam -obj $params -name "account_locked" -type "bool"
$groups = Get-AnsibleParam -obj $params -name "groups"
$groups_action = Get-AnsibleParam -obj $params -name "groups_action" -type "str" -default "replace" -validateset "add","remove","replace"

If ($account_locked -ne $null -and $account_locked) {
    Fail-Json $result "account_locked must be set to 'no' if provided"
}

If ($groups -ne $null) {
    If ($groups -is [System.String]) {
        [string[]]$groups = $groups.Split(",")
    }
    ElseIf ($groups -isnot [System.Collections.IList]) {
        Fail-Json $result "groups must be a string or array"
    }
    $groups = $groups | ForEach { ([string]$_).Trim() } | Where { $_ }
    If ($groups -eq $null) {
        $groups = @()
    }
}

$user_obj = Get-User $username

If ($state -eq 'present') {
    # Add or update user
    try {
        If (-not $user_obj) {
            New-ADUser $username
            $user_obj = Get-User $username
            If ($password -ne $null) {
                Set-ADAccountPassword $username -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $password -Force)
            }
            $result.msg = "New user created."
            $result.changed = $true
        }
        ElseIf (($password -ne $null) -and ($update_password -eq 'always')) {
            # ValidateCredentials will fail if either of these are true- just force update...
            If(-not $user_obj.Enabled -or $user_obj.PasswordExpired) {
                $password_match = $false
            }
            Else {
                $CurrentDomain = "LDAP://" + ([ADSI]"").distinguishedName
                $domain = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,$userName,$password)
                if ($domain.name -eq $null)
                {
                    $password_match = $false
                    $result.msg += "Password will be reset."
                }
                else
                {
                    $password_match = $true
                    $result.msg += "Password will not be reset."
                }
            }

            If (-not $password_match) {
                Set-ADAccountPassword $username -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $password -Force)
                $result.changed = $true
                $result.msg += "Password set because password match is $password_match."
            }
        }
        If (($upn -ne $null) -and ($upn -ne $user_obj.UserPrincipalName)) {
            $user_obj.UserPrincipalName = $upn
            $result.changed = $true
            $result.msg += "UPN: $upn."
        }
        If (($description -ne $null) -and ($description -ne $user_obj.Description)) {
            $user_obj.Description = $description
            $result.changed = $true
            $result.msg += "Description: $description."
        }
        If (($password_expired -ne $null) -and ($password_expired -ne ($user_obj.PasswordExpired | ConvertTo-Bool))) {
            Set-ADUser $username -ChangePasswordAtLogon:$password_expired
            $result.changed = $true
            $result.msg += "Password expired: $password_expired."
        }
        If (($password_never_expires -ne $null) -and ($password_never_expires -ne (Get-UserFlag $username $ADS_UF_DONT_EXPIRE_PASSWD))) {
            If ($password_never_expires) {
                Set-UserFlag $user_obj $ADS_UF_DONT_EXPIRE_PASSWD
            }
            Else {
                Clear-UserFlag $user_obj $ADS_UF_DONT_EXPIRE_PASSWD
            }
            $result.changed = $true
        }
        If (($user_cannot_change_password -ne $null) -and ($user_cannot_change_password -ne (Get-UserFlag $username $ADS_UF_PASSWD_CANT_CHANGE))) {
            If ($user_cannot_change_password) {
                Set-UserFlag $user_obj $ADS_UF_PASSWD_CANT_CHANGE
                $result.msg += "Checked user cannot change password."
            }
            Else {
                Clear-UserFlag $user_obj $ADS_UF_PASSWD_CANT_CHANGE
                $result.msg += "Unchecked user cannot change password."
            }
            $result.changed = $true
        }
        If (($account_enabled -ne $null) -and ($account_enabled -ne $user_obj.Enabled)) {
            $user_obj.Enabled = $account_enabled
            $result.changed = $true
            $result.msg += "Account enabled."
        }
        If (($account_locked -ne $null) -and ($account_locked -ne $user_obj.LockedOut)) {
            Unlock-ADAccount -Identity $username
            $result.changed = $true
            $result.msg += "Account unlocked."
        }
        If ($null -ne $groups) {
            if ((Get-ADUser -Filter 'SamAccountName -like $username' -Properties *).MemberOf | Get-ADGroup)
            { 
                $current_groups = @(((Get-ADUser -Filter 'SamAccountName -like $username' -Properties *).MemberOf | Get-ADGroup).Name)
            }
            else 
            {
                $current_groups = @("Domain Users")
            }
            $result.msg += "Current groups: $current_groups"
            If (($groups_action -eq "remove") -or ($groups_action -eq "replace")) {
                ForEach ($grp in $groups) {
                    If ((($groups_action -eq "remove") -and ($groups -contains $grp)) -or (($groups_action -eq "replace") -and ($groups -notcontains $grp))) {
                        $group_obj = Get-ADGroup $grp -Properties *
                        If ($group_obj) {
                            if ($group_obj.Member -notlike ($user_obj.DistinguishedName))
                            {
                                Remove-ADGroupMember $grp $username -Confirm:$false
                                $result.changed = $true
                                $result.msg += "Removed $username from $grp. Groups: $groups"
                            }
                        }
                        Else {
                            Fail-Json $result "group '$grp' not found"
                        }
                    }
                }
            }
            If (($groups_action -eq "add") -or ($groups_action -eq "replace")) {
                ForEach ($grp in $groups) {
                    If ($current_groups -notcontains $grp) {
                        $group_obj = Get-ADGroup $grp
                        If ($group_obj) {
                            Add-ADGroupMember $grp $user_obj.objectSid
                            $result.changed = $true
                            $result.msg += "Added $username to $grp. Groups: $groups"
                        }
                        Else {
                            Fail-Json $result "group '$grp' not found"
                        }
                    }
                }
            }
        }
        If ($result.changed) {
            Set-ADUser -instance $user_obj
        }
        If (($fullname -ne $null) -and ($fullname -ne $user_obj.DisplayName) -and ($fullname -ne (Get-ADObject -Identity (Get-User $username).DistinguishedName -Properties *).CN)) {
            $user_obj.DisplayName = $fullname
            $user_obj.GivenName = ($fullname -split " ")[0]
            $user_obj.Surname = ($fullname -split " ")[1]
            Set-ADUser -instance $user_obj
            Rename-ADObject -Identity (Get-User $username).DistinguishedName -NewName $fullname
            $result.msg += "Full name set to $fullname"
            $result.changed = $true
        }
        If (($ou -ne $null) -and ($ou -ne ($user_obj.distinguishedName -replace '^.+?,(CN|OU.+)','$1')) ) {
            Move-ADObject (Get-User $username).ObjectGUID -TargetPath $ou
            $result.msg += "OU set to $ou"
            $result.changed = $true
        }
    }
    catch {
        Fail-Json $result $_.Exception.Message
    }
}
ElseIf ($state -eq 'absent') {
    # Remove user
    try {
        If ($user_obj) {
            Remove-ADUser -Confirm:$false -Identity $username
            $result.changed = $true
            $result.msg = "User '$username' deleted successfully"
            $user_obj = $null
        } else {
            $result.msg = "User '$username' was not found"
        }
    }
    catch {
        Fail-Json $result $_.Exception.Message
    }
}

try {
    $user_obj = Get-ADUser -Filter 'SamAccountName -like $username' -Properties *
    If ($user_obj) {
        $result.name = $user_obj.Name
        $result.fullname = $user_obj.DisplayName
        $result.path = $user_obj.DistinguishedName
        $result.description = $user_obj.Description
        $result.password_expired = $user_obj.PasswordExpired
        $result.password_never_expires = $user_obj.PasswordNeverExpires
        $result.user_cannot_change_password = $user_obj.CannotChangePassword
        $result.account_enabled = $user_obj.Enabled
        $result.account_locked = $user_obj.LockedOut
        $result.sid = $user_obj.SID.Value
        $user_groups = @()
        ForEach ($grp in ($user_obj.MemberOf | Get-ADGroup).Name) {
            $group_result = @{
                name = $grp
                path = (Get-ADGroup $grp).DistinguishedName
            }
            $user_groups += $group_result;
        }
        $result.groups = $user_groups
        $result.state = "present"
    }
    Else {
        $result.name = $username
        if ($state -eq 'query') {
            $result.msg = "User '$username' was not found"
        }
        $result.state = "absent"
    }
} 
catch {
    Fail-Json $result $_.Exception.Message
}

Exit-Json $result
