<#
    .SYNOPSIS
        Searches for a supplied list of SHA1 or SHA256 hashes on a system. Requires either a file size or creation date that is associated with the binary that the 
        hashes were retrieved from.

    .DESCRIPTION
        Rather than hashing the whole filesystem, it hashes files that match the supplied file size or creation date and then checks to see if any of them matches the 
        list of SHA1 or SHA256 hashe. If a match is found, it can be deleted, if desired. All matches are written to a CSV.

    .PARAMETER Directory
        Used to supply a directory to recursively search

    .PARAMETER Drive
        Used to supply a drive or partition to recursively search

    .PARAMETER OSDrive
        Used to recursively search the drive that the operating system is installed on

    .PARAMETER CreationDate
        Used to supply a creation date; files matching this will be hashed

    .PARAMETER FileSize
        Used to supply a file size in bytes; files matching this will be hashed

    .PARAMETER ExportDirectory
        Used to depict where to create results file; default location is c:\windows\temp

    .EXAMPLE
        PS C:\ > .\Invoke-HashFinder -Directory "c:\users\administrator" -CreationDate "06/13/2020"

        Hashes files within and recursive of "c:\users\administrator" that have a creation date of June 13, 2020 and then checks for matches in the SHA1 and SHA256 list 
        on line 76. All matches will be deleted and there will be an entry written to a CSV file in "c:\windows\temp".

    .EXAMPLE
        PS C:\ > .\Invoke-HashFinder -Directory "c:\users\administrator" -CreationDate "12/20/2020" -LogOnly

        Hashes files within and recursive of "c:\users\administrator" that have a creation date of December 20, 2020 and then checks for matches in the SHA1 and SHA256 list 
        on line 76. All matches will have an entry written to a CSV file in "c:\windows\temp". The file WILL NOT be deleted.

    .EXAMPLE
        PS C:\ > .\Invoke-HashFinder -Directory "c:\users\administrator" -FileSize "1044"

        Hashes files within and recursive of "c:\users\administrator" that have a file size of 1044 bytes and then checks for matches in the SHA1 and SHA256 list 
        on line 76. All matches will be deleted and there will be an entry written to a CSV file in "c:\windows\temp".

    .EXAMPLE
        PS C:\ > .\Invoke-HashFinder -Drive "D:\" -FileSize "8426" -ExportDirectory "C:\"

        Hashes files within and recursive of "d:\" that have a file size of 8426 bytes and then checks for matches in the SHA1 and SHA256 list 
        on line 76. All matches will be deleted and there will be an entry written to a CSV file in "c:\".

    .EXAMPLE
        PS C:\ > .\Invoke-HashFinder -OSDrive -FileSize "4512" -ExportDirectory "C:\"

        Hashes files within and recursive of the drive that the operating system is installed on that have a file size of 4512 bytes and then checks for matches in the 
        SHA1 and SHA256 list on line 76. All matches will be deleted and there will be an entry written to a CSV file in "c:\".

    .NOTES  
        File Name      : Invoke-HashFinder.ps1
        Version        : v.0.2
        Author         : @WiredPulse
        Created        : 6 Feb 21
#>

    [CmdletBinding()]
    param(
        [string]$Directory,
        [string]$Drive,
        [switch]$OSDrive,
        [datetime]$CreationDate,
        [string]$FileSize,
        [string]$ExportDirectory = "c:\windows\temp\$env:COMPUTERNAME.txt",
        [switch]$LogOnly
    )

    # Input Hashes here
    $global:sha256 = @()
    $global:sha1 = @()


    function hashSize($path, $FileSize, $ExportDirectory){
        $fullPath =@()
        $fullPath = (Get-ChildItem $path -recurse -File | Where-Object{$_.Length -eq $FileSize}).FullName
        Hasher -fullpath $fullPath -ExportDirectory $ExportDirectory
    } 

    function hashDate($path, $CreationDate, $ExportDirectory){
        $fullPath =@()
        $fullPath = (Get-ChildItem $path -recurse -File -ErrorAction SilentlyContinue | Where-Object{$_.CreationTime -gt $CreationDate}).FullName 
        Hasher -fullpath $fullPath -ExportDirectory $ExportDirectory
    }  
   
    function hash($path, $ExportDirectory){
        $fullPath =@()
        $fullPath = (Get-ChildItem $path -recurse -File).FullName            
        Hasher -fullpath $fullPath -ExportDirectory $ExportDirectory 
    }

    function hasher($fullpath, $ExportDirectory){
            ForEach($file in $fullPath){
            Remove-Variable hash -ErrorAction SilentlyContinue
            try{
                $hash1 = Get-FileHash $file -Algorithm SHA1 -ErrorAction stop 
                if($sha1 -Contains $hash1.hash){
                    try{
                    if($LogOnly){
                        $file = $false
                    }
                    remove-item $file -Force -ErrorAction stop
                    $hash1 | Add-Member -NotePropertyName "Deleted" -NotePropertyValue "True" -ErrorAction stop
                    $hash1 | Export-Csv $ExportDirectory -Append 
                    }
                    catch{
                        $hash1 | Add-Member -NotePropertyName "Deleted" -NotePropertyValue "False"| Export-Csv $ExportDirectory -Append    
                        $hash1 | Export-Csv $ExportDirectory -Append 
                    }
                }
            }
            catch{
                [pscustomobject]@{
                        Algorithm = "SHA1"
                        Hash = "Couldn't Retrieve Hash"
                        Path = $file
                        Deleted = "False"
                } | Export-Csv $ExportDirectory -Append 
            }
          try{
                if(-not(Test-Path $file)){
                    continue
                }

                $hash256 = Get-FileHash $file -Algorithm SHA256 -ErrorAction stop 
                if($sha256 -Contains $hash256.hash){
                    try{
                    if($LogOnly){
                        $file = $false
                    }
                    remove-item $file -Force -ErrorAction stop
                    $hash256 | Add-Member -NotePropertyName "Deleted" -NotePropertyValue "True" -ErrorAction stop
                    $hash256 | Export-Csv $ExportDirectory -Append 
                    }
                    catch{
                        $hash256 | Add-Member -NotePropertyName "Deleted" -NotePropertyValue "False"| Export-Csv $ExportDirectory -Append    
                        $hash256 | Export-Csv $ExportDirectory -Append 
                    }
                }
            }
           catch{
                [pscustomobject]@{
                        Algorithm = "SHA256"
                        Hash = "Couldn't Retrieve Hash"
                        Path = $file
                        Deleted = "False"
                } | Export-Csv $ExportDirectory -Append 
            }
        } 


    }

    if($Directory){
        if(Test-Path $Directory){
            $path = $Directory
        }
        else{
            Write-Error -Message "Directory doesn't exist"
        }
    }
    elseif($Drive){
        if($Drive -notlike "*:\"){
            $Drive = $Drive[0] + ":\"
        }
        if(Test-Path $Drive){
            $path = $Drive
        }
        else{
            Write-Error -Message "Drive doesn't exist"
        }
    }
    elseif($OSDrive){
        $path = $env:SystemDrive + "\"
    }
    else{
        Write-Error -Message "A directory, drive, or system drive parameter has to be supplied"
    }


    if($CreationDate){
        hashDate -path $path -CreationDate $CreationDate -ExportDirectory $ExportDirectory
    }
    elseif($FileSize){
        hashSize -path $path -FileSize $FileSize -ExportDirectory $ExportDirectory
    }
    else{
        hash -path $path -ExportDirectory $ExportDirectory
    }

