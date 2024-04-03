
function Show-Options {
    Write-Host "Acik uygulamaları goster"
    Write-Host "Uygulama kapat"
    Write-Host "Dll Inject"
}


function Show-OpenFiles {
    Get-Process | Where-Object { $_.MainWindowTitle -ne "" } | Select-Object MainWindowTitle
}


function Close-Application {
    param(
        [string]$AppName
    )
    Stop-Process -Name $AppName
}

function Inject-DLL {
    param(
        [string]$ProcessName,
        [string]$DLLPath
    )
    $process = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
    if ($process) {
        $processHandle = $process.Handle
        $kernel32 = Add-Type -MemberDefinition @"
            [DllImport("kernel32.dll")]
            public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

            [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
            public static extern IntPtr GetModuleHandle(string lpModuleName);

            [DllImport("kernel32", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);

            [DllImport("kernel32.dll")]
            public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

            [DllImport("kernel32.dll")]
            public static extern int GetLastError();

            [DllImport("kernel32.dll")]
            public static extern bool CloseHandle(IntPtr hObject);
"@ -Name "Kernel32" -Namespace Win32Functions -PassThru

        $processHandle = $process.Id
        $processHandle = [Win32Functions.Kernel32]::OpenProcess(0x1F0FFF, $false, $processHandle)
        $addr = [Win32Functions.Kernel32]::GetProcAddress([Win32Functions.Kernel32]::GetModuleHandle("kernel32.dll"), "LoadLibraryA")
        $size = 1 + $DLLPath.Length
        $allocation = [Win32Functions.Kernel32]::VirtualAllocEx($processHandle, 0, $size, 0x3000, 0x40)
        [Win32Functions.Kernel32]::WriteProcessMemory($processHandle, $allocation, [System.Text.Encoding]::ASCII.GetBytes($DLLPath), $size, [ref]::0)
        [Win32Functions.Kernel32]::CreateRemoteThread($processHandle, 0, 0, $addr, $allocation, 0, 0) | Out-Null
        [Win32Functions.Kernel32]::CloseHandle($processHandle) | Out-Null
    } else {
        Write-Host "Belirtilen islem bulunamadi."
    }
}


while ($true) {
    Show-Options
    $choice = Read-Host "Lutfen bir secenek secin (1, 2 veya 3):"

    switch ($choice) {
        1 { Show-OpenFiles }
        2 {
            $appName = Read-Host "Kapatmak istediginiz uygulamanin adini girin:"
            Close-Application -AppName $appName
        }
        3 {
            $processName = Read-Host "DLL injectlemek istediğiniz işlemin adini girin:"
            $dllPath = Read-Host "Injectlemek istediğiniz DLL'nin dosya yolunu girin:"
            Inject-DLL -ProcessName $processName -DLLPath $dllPath
        }
        default { Write-Host "Geçersiz seçenek, lütfen tekrar deneyin." }
    }

    $continue = Read-Host "Devam etmek istiyor musunuz? (E/H)"
    if ($continue -ne "E") {
        break
    }
}
