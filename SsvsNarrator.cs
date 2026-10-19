// SsvsNarrator - external (read-only) screen-reader narrator for SAMURAI SHODOWN V SPECIAL.
// Route D: ReadProcessMemory into the game's MenuManager/MainMenu structures; announce the
// current menu + selected item via NVDA (controller client), UIA notification, or SAPI.
// No code injection. Target: SSVS.exe (x86, image base 0x00400000, no ASLR).
//
// RE facts (confirmed live):
//   MenuManager vtable        = 0x004b9874
//   MenuManager + 0x1c        = current menu object pointer
//   MainMenu vtable           = 0x004b7fb4
//   menu + 0x6c               = label pointer array (char* keys)
//   menu + 0x78               = item count
//   menu + 0x28               = selected node name ("lineN", N 1-based)
//   menu + 0x94               = selected index (0-based, fallback)
//   label array[idx]          = char* key; resolved through Data\strings.txt (col1 key -> col3 en)
//
// Menu family layout (confirmed by vtable dump + decompiling the shared refresh FUN_004513d0):
//   Every menu class shares one base layout and a uniform 27-slot vtable, so +0x28 / +0x6c are
//   valid on all of them:
//     MainMenu 0x004b7fb4, OptionsMenu 0x004b8264, PauseMenu 0x004b8334, PopupMenu 0x004b8514,
//     OverlayMenu 0x004b9a3c, StandardMenu 0x004b9bb4, DummyMenu 0x004b977c, base Menu 0x004b970c
//   FUN_004513d0 (refresh) READS +0x78/+0x6c and creates nodes "line1".."lineN" via
//   FUN_004485d0("lineN", key->display, 0). The count at +0x78 is written by each menu's item
//   builder, so MainMenu/OptionsMenu/StandardMenu (which run it) have a valid count, while
//   PopupMenu/OverlayMenu leave +0x78 at allocator junk -> this narrator derives the count from
//   the label array in that case (see DeriveCount).

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;

static class SsvsNarrator
{
    // ---- game RE constants ----
    const uint MENU_MANAGER_VTABLE = 0x004b9874u;
    const long OFF_MGR_MENU       = 0x1c;
    const long OFF_MENU_LABELARR  = 0x6c;
    const long OFF_MENU_COUNT     = 0x78;
    const long OFF_MENU_SELNAME   = 0x28;
    const long OFF_MENU_SELIDX    = 0x94;
    const uint RDATA_LO = 0x004b0000u;
    const uint RDATA_HI = 0x00520000u;

    // ---- Win32 ----
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, IntPtr nSize, out IntPtr lpNumberOfBytesRead);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, IntPtr dwLength);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool SetDllDirectory(string lpPathName);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool QueryFullProcessImageName(IntPtr hProcess, int dwFlags, StringBuilder lpExeName, ref int lpdwSize);
    [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, StringBuilder lpFilename, int nSize);
    [DllImport("psapi.dll", SetLastError = true)]
    static extern bool EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr[] lphModule, uint cb, out uint lpcbNeeded, uint dwFilterFlag);
    [DllImport("user32.dll")]
    static extern short GetAsyncKeyState(int vKey);
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern bool GetUserObjectInformation(IntPtr hObj, int nIndex, StringBuilder pvInfo, int nLength, out int lpnLengthNeeded);
    [DllImport("user32.dll")]
    static extern IntPtr GetThreadDesktop(int dwThreadId);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [StructLayout(LayoutKind.Sequential)]
    struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID Luid;
        public uint Attributes;
    }

    const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    const uint TOKEN_QUERY = 0x0008;
    const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [DllImport("kernel32.dll")]
    static extern int GetCurrentThreadId();

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX, dwY, dwXSize, dwYSize;
        public int dwXCountChars, dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcess(
        string lpApplicationName, string lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
        bool bInheritHandles, uint dwCreationFlags,
        IntPtr lpEnvironment, string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation
    );

    // ---- Prism universal speech engine ----
    [DllImport("prism.dll", CallingConvention = CallingConvention.Cdecl)]
    static extern IntPtr prism_init(IntPtr cfg);
    [DllImport("prism.dll", CallingConvention = CallingConvention.Cdecl)]
    static extern IntPtr prism_registry_acquire_best(IntPtr ctx);
    [DllImport("prism.dll", CallingConvention = CallingConvention.Cdecl)]
    static extern IntPtr prism_backend_name(IntPtr backend);
    [DllImport("prism.dll", CallingConvention = CallingConvention.Cdecl)]
    static extern int prism_backend_initialize(IntPtr backend);
    [DllImport("prism.dll", CallingConvention = CallingConvention.Cdecl)]
    static extern int prism_backend_speak(IntPtr backend, byte[] utf8Bytes, bool interrupt);
    [DllImport("prism.dll", CallingConvention = CallingConvention.Cdecl)]
    static extern void prism_shutdown(IntPtr ctx);

    // ---- NVDA controller client ----
    [DllImport("nvdaControllerClient.dll", CharSet = CharSet.Unicode)]
    static extern int nvdaController_speakText(string text);
    [DllImport("nvdaControllerClient.dll")]
    static extern int nvdaController_testIfRunning();
    [DllImport("nvdaControllerClient.dll")]
    static extern int nvdaController_cancelSpeech();

    // ---- UIA notification ----
    [DllImport("UIAutomationCore.dll")]
    static extern int UiaHostProviderFromHwnd(IntPtr hwnd, out IntPtr provider);
    [DllImport("UIAutomationCore.dll", CharSet = CharSet.Unicode)]
    static extern int UiaRaiseNotificationEvent(IntPtr provider, int notificationKind, int notificationProcessing, string displayString, string activityId);

    [StructLayout(LayoutKind.Sequential)]
    struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public int __pad1;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
        public int __pad2;
    }

    const uint PROCESS_VM_READ = 0x0010;
    const uint PROCESS_QUERY_INFORMATION = 0x0400;
    const uint MEM_COMMIT = 0x1000;
    const uint PAGE_READWRITE = 0x04;
    const uint PAGE_WRITECOPY = 0x08;
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint PAGE_EXECUTE_WRITECOPY = 0x80;

    const int CHUNK = 4 * 1024 * 1024;

    // ---- runtime state ----
    static IntPtr hProc = IntPtr.Zero;
    static long targetModuleBase = 0x00400000L;
    static long baseDelta = 0;
    static long mgr = 0;
    static string currentLang = "pt";
    static Dictionary<string, string> stringMap = new Dictionary<string, string>();
    static Dictionary<string, Dictionary<string, string>> allStrings = new Dictionary<string, Dictionary<string, string>>();
    static string cachedStringsPath = null;
    static string lastDedup = null;
    static bool verbose = false;
    static IntPtr prismCtx = IntPtr.Zero;
    static IntPtr prismBackend = IntPtr.Zero;
    static string prismBackendName = null;
    static bool mute = false;
    static bool shouldExit = false;
    static string speakerMode = "auto";
    static bool[] keyWasDown = new bool[256];
    static string manualGamePath = null;

    static object sapi = null;
    static IntPtr uiaProvider = IntPtr.Zero;
    static Form uiaForm = null;

    static uint dynamicMenuManagerVtable = 0;
    static long dynamicMenuManagerPtr = 0;
    static long dynamicNeoBankTable = 0;

    static int IndexOfBytes(byte[] source, byte[] pattern, int start)
    {
        for (int i = start; i <= source.Length - pattern.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < pattern.Length; j++)
            {
                if (source[i + j] != pattern[j]) { match = false; break; }
            }
            if (match) return i;
        }
        return -1;
    }

    static void AutoScanTargetSignatures(IntPtr h, long modBase)
    {
        try
        {
            Log("--- Iniciando Auto-Scan dinamico de assinaturas no SSVS.exe ---");
            int scanSize = 1024 * 1024; // 1 MB
            byte[] text = ReadBytes(h, modBase, scanSize);
            if (text == null || text.Length < 0x1000)
            {
                Log("[Auto-Scan] Nao foi possivel ler os primeiros bytes do modulo.");
                return;
            }

            // 1. Scan for MenuManager constructor: 33 c0 89 46 04 89 46 10 89 46 14 d9 ee
            byte[] ctorPat = new byte[] { 0x33, 0xc0, 0x89, 0x46, 0x04, 0x89, 0x46, 0x10, 0x89, 0x46, 0x14, 0xd9, 0xee };
            int ctorPos = IndexOfBytes(text, ctorPat, 0);
            if (ctorPos != -1)
            {
                for (int i = ctorPos; i < ctorPos + 30 && i + 6 <= text.Length; i++)
                {
                    if (text[i] == 0xc7 && text[i + 1] == 0x06)
                    {
                        dynamicMenuManagerVtable = BitConverter.ToUInt32(text, i + 2);
                        Log(string.Format("[Auto-Scan] VTable MenuManager descoberta: 0x{0:X}", dynamicMenuManagerVtable));
                        break;
                    }
                }
            }

            // 2. Scan for MenuManager instantiation call and global pointer write:
            // 8b f0 eb 02 33 f6 53 56 -> within 35 bytes find 89 35 [ptr]
            byte[] ptrPat = new byte[] { 0x8b, 0xf0, 0xeb, 0x02, 0x33, 0xf6, 0x53, 0x56 };
            int ptrPos = IndexOfBytes(text, ptrPat, 0);
            if (ptrPos != -1)
            {
                for (int i = ptrPos; i < ptrPos + 40 && i + 6 <= text.Length; i++)
                {
                    if (text[i] == 0x89 && text[i + 1] == 0x35)
                    {
                        uint p = BitConverter.ToUInt32(text, i + 2);
                        dynamicMenuManagerPtr = p;
                        Log(string.Format("[Auto-Scan] Ponteiro global MenuManager descoberto: 0x{0:X}", dynamicMenuManagerPtr));
                        break;
                    }
                }
            }

            // 3. Scan for 68000 bank table: c1 e9 10 8b 0c 8d or c1 e8 10 8b 04 85 or c1 e9 10 8b 04 8d
            byte[][] bankPats = new byte[][]
            {
                new byte[] { 0xc1, 0xe9, 0x10, 0x8b, 0x0c, 0x8d },
                new byte[] { 0xc1, 0xe9, 0x10, 0x8b, 0x04, 0x8d },
                new byte[] { 0xc1, 0xe8, 0x10, 0x8b, 0x04, 0x85 }
            };
            foreach (byte[] bp in bankPats)
            {
                int bPos = IndexOfBytes(text, bp, 0);
                if (bPos != -1 && bPos + bp.Length + 4 <= text.Length)
                {
                    dynamicNeoBankTable = BitConverter.ToUInt32(text, bPos + bp.Length);
                    Log(string.Format("[Auto-Scan] Tabela Neo-Geo RAM descoberta: 0x{0:X}", dynamicNeoBankTable));
                    break;
                }
            }
        }
        catch (Exception ex)
        {
            Log("[Auto-Scan] Erro durante auto-scan: " + ex.Message);
        }
    }

    static long ResolveAddr(long origVa)
    {
        return origVa + baseDelta;
    }

    static long GetTargetModuleBase(IntPtr hp)
    {
        try
        {
            IntPtr[] mods = new IntPtr[256];
            uint needed;
            // 0x03 = LIST_MODULES_ALL, 0x01 = LIST_MODULES_32BIT
            if (EnumProcessModulesEx(hp, mods, (uint)(IntPtr.Size * mods.Length), out needed, 0x03) && needed > 0)
            {
                long baseAddr = mods[0].ToInt64();
                if (baseAddr >= 0x10000) return baseAddr;
            }
        }
        catch (Exception ex)
        {
            Log("GetTargetModuleBase aviso: " + ex.Message);
        }
        return 0x00400000L;
    }

    static string logFilePath = null;
    static readonly object logLock = new object();

    static void InitLog()
    {
        try
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            logFilePath = Path.Combine(baseDir, "log.txt");
            string header = string.Format(
                "================================================================================\r\n" +
                "  SsvsNarrator Log Iniciado: {0}\r\n" +
                "  PID: {1} | 64-bit Process: {2} | OS: {3}\r\n" +
                "  Diretorio Base: {4}\r\n" +
                "================================================================================\r\n",
                DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff"),
                Process.GetCurrentProcess().Id,
                Environment.Is64BitProcess,
                Environment.OSVersion,
                baseDir
            );
            File.WriteAllText(logFilePath, header, Encoding.UTF8);
        }
        catch (Exception ex)
        {
            try
            {
                logFilePath = Path.Combine(Path.GetTempPath(), "ssvs_narrator_log.txt");
                File.WriteAllText(logFilePath, "Fallback log: " + ex.Message + "\r\n", Encoding.UTF8);
            }
            catch { }
        }
    }

    static void Log(string msg)
    {
        string line = DateTime.Now.ToString("HH:mm:ss.fff") + " [pid=" + Process.GetCurrentProcess().Id + "] " + msg;
        try { Console.WriteLine(line); } catch { }

        lock (logLock)
        {
            try
            {
                if (logFilePath == null) InitLog();
                File.AppendAllText(logFilePath, line + "\r\n", Encoding.UTF8);
            }
            catch { }
        }
    }

    static void KillPreviousInstances()
    {
        try
        {
            int currentPid = Process.GetCurrentProcess().Id;
            Process[] ps = Process.GetProcessesByName("SsvsNarrator");
            foreach (Process p in ps)
            {
                try
                {
                    if (p.Id != currentPid)
                    {
                        Log("[INSTANCIA ANTERIOR] Encontrada instancia anterior em execucao (PID=" + p.Id + "). Finalizando...");
                        p.Kill();
                        p.WaitForExit(2000);
                        Log("[INSTANCIA ANTERIOR] Instancia anterior PID=" + p.Id + " finalizada com sucesso.");
                    }
                }
                catch (Exception ex)
                {
                    Log("[INSTANCIA ANTERIOR] Nao foi possivel finalizar PID=" + p.Id + ": " + ex.Message);
                }
            }
        }
        catch (Exception ex)
        {
            Log("Erro ao verificar instancias anteriores: " + ex.Message);
        }
    }

    static void EnableDebugPrivilege()
    {
        try
        {
            IntPtr hToken;
            if (OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
            {
                try
                {
                    LUID luid;
                    if (LookupPrivilegeValue(null, "SeDebugPrivilege", out luid))
                    {
                        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
                        tp.PrivilegeCount = 1;
                        tp.Luid = luid;
                        tp.Attributes = SE_PRIVILEGE_ENABLED;
                        AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                        Log("SeDebugPrivilege habilitado com sucesso.");
                    }
                }
                finally
                {
                    CloseHandle(hToken);
                }
            }
        }
        catch (Exception ex)
        {
            Log("Aviso ao habilitar SeDebugPrivilege: " + ex.Message);
        }
    }

    static bool RelaunchAsAdmin(string[] args)
    {
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = Assembly.GetExecutingAssembly().Location;
            psi.Arguments = string.Join(" ", args);
            psi.Verb = "runas";
            psi.UseShellExecute = true;
            Process.Start(psi);
            return true;
        }
        catch (Exception ex)
        {
            Log("RelaunchAsAdmin failed: " + ex.Message);
            return false;
        }
    }

    static bool IsProcessAlive(int pid)
    {
        if (pid <= 0) return false;
        try
        {
            IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (h == IntPtr.Zero) h = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
            if (h != IntPtr.Zero)
            {
                try
                {
                    uint exitCode;
                    if (GetExitCodeProcess(h, out exitCode))
                        return exitCode == 259; // STILL_ACTIVE = 259
                }
                finally
                {
                    CloseHandle(h);
                }
            }

            Process p = Process.GetProcessById(pid);
            try { return !p.HasExited; }
            catch { return true; } // If Access Denied, process is running!
        }
        catch { return false; }
    }

    static Mutex singleInstanceMutex = null;

    [STAThread]
    static int Main(string[] args)
    {
        InitLog();
        AppDomain.CurrentDomain.UnhandledException += (s, e) => {
            Log("FATAL: " + e.ExceptionObject);
        };
        try { Console.OutputEncoding = Encoding.UTF8; } catch { }

        Log("SsvsNarrator iniciado. Argumentos: " + (args.Length == 0 ? "(nenhum)" : string.Join(" ", args)));

        KillPreviousInstances();

        bool createdNew;
        singleInstanceMutex = new Mutex(true, @"Local\SsvsNarrator_SingleInstance_Mahi", out createdNew);
        if (!createdNew)
        {
            Log("Aviso: Outra instancia ainda respondia ao Mutex. Continuando como nova sessao ativa...");
        }

        int pid = 0;
        string stringsPath = null;
        int interval = 120;
        int durationSec = 0;
        bool listOnly = false;
        bool dumpOnly = false;

        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            if (a == "-Pid" && i + 1 < args.Length) { int v; if (int.TryParse(args[++i], out v)) pid = v; }
            else if ((a == "-Game" || a == "-Path" || a == "-Exe") && i + 1 < args.Length) manualGamePath = args[++i];
            else if (a == "-Strings" && i + 1 < args.Length) stringsPath = args[++i];
            else if (a == "-Interval" && i + 1 < args.Length) { int v; if (int.TryParse(args[++i], out v)) interval = v; }
            else if (a == "-Speaker" && i + 1 < args.Length) speakerMode = args[++i].ToLowerInvariant();
            else if (a == "-Duration" && i + 1 < args.Length) { int v; if (int.TryParse(args[++i], out v)) durationSec = v; }
            else if (a == "-Verbose") verbose = true;
            else if (a == "-Mute") mute = true;
            else if (a == "--list") listOnly = true;
            else if (a == "--dump") dumpOnly = true;
        }

        if (string.IsNullOrEmpty(manualGamePath))
            manualGamePath = LoadSavedGamePath();

        Log("Caminho do jogo (config/argumento): " + (manualGamePath ?? "(nenhum configurado)"));

        try { SetDllDirectory(AppDomain.CurrentDomain.BaseDirectory); } catch { }

        Log("--- Verificando sintetizadores de voz ---");
        int nvdaStatus = -1;
        try { nvdaStatus = nvdaController_testIfRunning(); } catch (Exception ex) { Log("nvdaController_testIfRunning falhou: " + ex.Message); }
        Log("NVDA rodando: " + (nvdaStatus == 0 ? "SIM (0)" : "NAO (" + nvdaStatus + ")"));

        bool prismOk = false;
        try { prismOk = InitPrism(); } catch (Exception ex) { Log("InitPrism falhou: " + ex.Message); }
        Log("Prism backend: " + (prismOk ? prismBackendName : "Nao disponivel"));

        Log("Testando emissao de fala inicial...");
        Speak("Narrador Samurai Shodown V Special ativado.");

        // resolve target pid first when we need to derive the strings path
        Log("Buscando processo SSVS...");
        if (pid == 0) pid = FindPid();
        if (pid != 0) Log("Processo SSVS localizado inicialmente: PID=" + pid);
        else Log("Processo SSVS nao encontrado imediatamente. Entrando no loop de espera...");

        if (stringsPath == null)
            stringsPath = DeriveStringsPath(pid);
        cachedStringsPath = stringsPath;
        Log("Arquivo de strings definido: " + (stringsPath ?? "(nenhum localizado ainda)"));
        PreloadAllStrings(stringsPath);
        SetLanguage("pt");
        Log("Chaves de texto carregadas: " + stringMap.Count);

        if (listOnly)
        {
            Console.WriteLine("strings file : " + (stringsPath == null ? "(none)" : stringsPath));
            Console.WriteLine("keys loaded  : " + stringMap.Count);
            return 0;
        }

        if (pid == 0)
        {
            if (dumpOnly || listOnly)
            {
                Console.WriteLine("SSVS process not found. Start the game, or pass -Pid N.");
                return 1;
            }
            Console.WriteLine("Aguardando o jogo Samurai Shodown V Special (SSVS.exe) iniciar...");
            Console.WriteLine("[DICA] Se o jogo ja estiver aberto ou em outro local, pressione ESPACO ou 'O' para selecionar o SSVS.exe pelo Explorer do Windows.");
            Log("Waiting for SSVS.exe to start...");
            int waitCount = 0;
            while (!shouldExit && pid == 0)
            {
                pid = FindPid();
                if (pid != 0) break;

                // Check if user pressed SPACE, ENTER, or 'O' in console to browse for game executable manually
                try
                {
                    if (Console.KeyAvailable)
                    {
                        ConsoleKeyInfo ki = Console.ReadKey(true);
                        if (ki.Key == ConsoleKey.Spacebar || ki.Key == ConsoleKey.O || ki.Key == ConsoleKey.Enter)
                        {
                            string chosen = PromptForGamePath();
                            if (!string.IsNullOrEmpty(chosen))
                            {
                                manualGamePath = chosen;
                                pid = FindPid();
                                if (pid != 0) break;
                            }
                        }
                    }
                }
                catch { }

                waitCount++;
                // If waiting for more than 15 seconds (30 * 500ms) and manual path is not set, offer dialog automatically
                if (waitCount == 30 && string.IsNullOrEmpty(manualGamePath))
                {
                    Console.WriteLine("\nNao foi possivel detectar o jogo automaticamente ainda.");
                    Console.WriteLine("Abrindo janela do Windows Explorer para voce selecionar o SSVS.exe...");
                    string chosen = PromptForGamePath();
                    if (!string.IsNullOrEmpty(chosen))
                    {
                        manualGamePath = chosen;
                        pid = FindPid();
                        if (pid != 0) break;
                    }
                }

                Thread.Sleep(500);
            }
            if (shouldExit) return 0;
            if (stringsPath == null) stringsPath = DeriveStringsPath(pid);
            if (cachedStringsPath == null) cachedStringsPath = stringsPath;
            if (allStrings.Count == 0) PreloadAllStrings(stringsPath);
            SetLanguage(currentLang);
        }

        EnableDebugPrivilege();

        hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
        if (hProc == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            if (err == 5) // ERROR_ACCESS_DENIED
            {
                Log("OpenProcess returned ERROR_ACCESS_DENIED (5) for pid=" + pid + ". Requesting admin elevation via UAC...");
                Console.WriteLine("\n[ACESSO NEGADO] O jogo SSVS.exe esta rodando com permissoes elevadas.");
                Console.WriteLine("Solicitando permissao de Administrador (UAC) para conectar ao jogo...");
                if (RelaunchAsAdmin(args))
                {
                    return 0;
                }
            }
            Console.WriteLine("OpenProcess failed (err=" + err + "). Tente executar o narrador como Administrador.");
            return 1;
        }

        targetModuleBase = GetTargetModuleBase(hProc);
        baseDelta = targetModuleBase - 0x00400000L;
        Log(string.Format("SSVS.exe conectado! PID={0} Base=0x{1:X} Delta=0x{2:X} Strings={3}", pid, targetModuleBase, baseDelta, stringMap.Count));

        AutoScanTargetSignatures(hProc, targetModuleBase);

        Console.CancelKeyPress += delegate(object s, ConsoleCancelEventArgs e)
        {
            e.Cancel = true;
            shouldExit = true;
        };

        // Notify user audibly that the game process was connected and how to enter menus
        Speak("Jogo conectado. Se estiver na tela de apresentação, aperte Enter, Espaço ou Start no controle.");

        mgr = GetManager(hProc);
        if (mgr != 0) Log("MenuManager ativo inicialmente em: 0x" + mgr.ToString("X"));
        else Log("MenuManager ainda nao inicializado pelo jogo (aguardando usuario abrir menus)...");

        if (dumpOnly)
        {
            if (mgr == 0) { Console.WriteLine("MenuManager not found."); CloseHandles(); return 2; }
            Poll(true);
            CloseHandles();
            return 0;
        }

        Poll(true); // initial announcement

        Stopwatch sw = Stopwatch.StartNew();
        long lastPoll = 0;
        long lastHeartbeat = 0;

        while (!shouldExit)
        {
            long now = sw.ElapsedMilliseconds;
            if (durationSec > 0 && now >= (long)durationSec * 1000) break;

            if (pid == 0 || !IsProcessAlive(pid))
            {
                int np = FindPid();
                if (np != 0 && np != pid)
                {
                    if (hProc != IntPtr.Zero) CloseHandle(hProc);
                    pid = np;
                    hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
                    targetModuleBase = GetTargetModuleBase(hProc);
                    baseDelta = targetModuleBase - 0x00400000L;
                    mgr = 0;
                    ramBase = 0;
                    lastDedup = null;

                    string dynStrings = DeriveStringsPath(pid);
                    if (dynStrings != null)
                    {
                        cachedStringsPath = dynStrings;
                        PreloadAllStrings(dynStrings);
                        SetLanguage(currentLang);
                    }
                    Log(string.Format("SSVS.exe reconectado! PID={0} Base=0x{1:X}", pid, targetModuleBase));
                }
            }

            if (Edge(0x77)) Poll(true);                    // F8  repeat current
            if (Edge(0x78)) SpeakMenuName();               // F9  menu name only
            if (Edge(0x79))                                // F10 toggle mute
            {
                mute = !mute;
                Console.WriteLine(mute ? "MUTE on" : "MUTE off");
                if (!mute) Poll(true);
            }
            if (Edge(0x7A)) break;                         // F11 quit (primary: 0x7A = VK_F11)
            if (Edge(0x7B)) break;                         // F12 quit (alt; only seen with Ctrl/Alt held)

            if (now - lastPoll >= interval)
            {
                Poll(false);
                lastPoll = now;
            }

            if (now - lastHeartbeat >= 5000)
            {
                Log(string.Format("[Heartbeat] PID={0} Mgr=0x{1:X} NeoRAM=0x{2:X}", pid, mgr, ramBase));
                lastHeartbeat = now;
            }

            try { Application.DoEvents(); } catch { }
            Thread.Sleep(15);
        }

        Speak("Ssvs narrator stopped.");
        CloseHandles();
        return 0;
    }

    static void CloseHandles()
    {
        if (hProc != IntPtr.Zero) { CloseHandle(hProc); hProc = IntPtr.Zero; }
        if (uiaForm != null) { try { uiaForm.Dispose(); } catch { } uiaForm = null; }
        if (prismCtx != IntPtr.Zero)
        {
            try { prism_shutdown(prismCtx); } catch { }
            prismCtx = IntPtr.Zero;
            prismBackend = IntPtr.Zero;
        }
    }

    static string GetConfigFilePath()
    {
        try
        {
            return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ssvs_path.cfg");
        }
        catch
        {
            return "ssvs_path.cfg";
        }
    }

    static string LoadSavedGamePath()
    {
        try
        {
            string cfg = GetConfigFilePath();
            if (File.Exists(cfg))
            {
                string line = File.ReadAllText(cfg, Encoding.UTF8).Trim();
                if (!string.IsNullOrEmpty(line))
                {
                    if (File.Exists(line)) return line;
                    string maybeExe = Path.Combine(line, "SSVS.exe");
                    if (File.Exists(maybeExe)) return maybeExe;
                }
            }
        }
        catch { }
        return null;
    }

    static void SaveGamePath(string path)
    {
        if (string.IsNullOrEmpty(path)) return;
        try
        {
            string cfg = GetConfigFilePath();
            File.WriteAllText(cfg, path.Trim(), Encoding.UTF8);
            Log("Game path saved to config: " + path);
        }
        catch { }
    }

    static string PromptForGamePath()
    {
        string selectedPath = null;
        Thread t = new Thread(() =>
        {
            try
            {
                using (OpenFileDialog ofd = new OpenFileDialog())
                {
                    ofd.Title = "Selecione o executavel do jogo (SSVS.exe)";
                    ofd.Filter = "Executavel do Jogo (SSVS.exe)|SSVS.exe|Todos os Executaveis (*.exe)|*.exe|Todos os Arquivos (*.*)|*.*";
                    ofd.CheckFileExists = true;
                    ofd.CheckPathExists = true;
                    ofd.RestoreDirectory = true;

                    if (ofd.ShowDialog() == DialogResult.OK)
                    {
                        selectedPath = ofd.FileName;
                    }
                }
            }
            catch (Exception ex)
            {
                Log("PromptForGamePath dialog error: " + ex.Message);
            }
        });
        t.SetApartmentState(ApartmentState.STA);
        t.Start();
        t.Join();

        if (!string.IsNullOrEmpty(selectedPath) && File.Exists(selectedPath))
        {
            Console.WriteLine("Caminho do jogo selecionado: " + selectedPath);
            SaveGamePath(selectedPath);
            return selectedPath;
        }
        return null;
    }

    static string GetProcessPath(int targetPid)
    {
        if (targetPid == 0) return null;
        try
        {
            Process p = Process.GetProcessById(targetPid);
            string fn = p.MainModule.FileName;
            if (!string.IsNullOrEmpty(fn) && File.Exists(fn)) return fn;
        }
        catch { }

        IntPtr hp = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, targetPid);
        if (hp != IntPtr.Zero)
        {
            try
            {
                StringBuilder sb = new StringBuilder(1024);
                int size = sb.Capacity;
                if (QueryFullProcessImageName(hp, 0, sb, ref size) && size > 0)
                {
                    string path = sb.ToString();
                    if (!string.IsNullOrEmpty(path) && File.Exists(path)) return path;
                }
                sb.Length = 0;
                if (GetModuleFileNameEx(hp, IntPtr.Zero, sb, sb.Capacity) > 0)
                {
                    string path = sb.ToString();
                    if (!string.IsNullOrEmpty(path) && File.Exists(path)) return path;
                }
            }
            catch { }
            finally
            {
                CloseHandle(hp);
            }
        }
        return null;
    }

    static int FindPid()
    {
        // 0. If user provided or saved a specific game path, match against running processes
        if (!string.IsNullOrEmpty(manualGamePath))
        {
            try
            {
                string targetDir = Path.GetDirectoryName(Path.GetFullPath(manualGamePath));
                Process[] all = Process.GetProcesses();
                for (int i = 0; i < all.Length; i++)
                {
                    Process p = all[i];
                    try
                    {
                        string fullPath = GetProcessPath(p.Id);
                        if (!string.IsNullOrEmpty(fullPath))
                        {
                            if (string.Equals(Path.GetFullPath(fullPath), Path.GetFullPath(manualGamePath), StringComparison.OrdinalIgnoreCase))
                                return p.Id;
                            if (string.Equals(Path.GetDirectoryName(Path.GetFullPath(fullPath)), targetDir, StringComparison.OrdinalIgnoreCase) &&
                                string.Equals(Path.GetFileName(fullPath), "SSVS.exe", StringComparison.OrdinalIgnoreCase))
                                return p.Id;
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        // 1. Direct process name lookup (case-insensitive)
        try
        {
            Process[] ps = Process.GetProcessesByName("SSVS");
            if (ps != null && ps.Length > 0)
            {
                for (int i = 0; i < ps.Length; i++)
                {
                    try
                    {
                        int targetId = ps[i].Id;
                        if (targetId > 0 && IsProcessAlive(targetId))
                            return targetId;
                    }
                    catch { }
                }
            }
        }
        catch { }

        try
        {
            Process[] ps = Process.GetProcessesByName("ssvs");
            if (ps != null && ps.Length > 0)
            {
                for (int i = 0; i < ps.Length; i++)
                {
                    try
                    {
                        int targetId = ps[i].Id;
                        if (targetId > 0 && IsProcessAlive(targetId))
                            return targetId;
                    }
                    catch { }
                }
            }
        }
        catch { }

        // 2. Scan all running processes for SSVS.exe (handles any renamed process or launcher scenario)
        try
        {
            Process[] all = Process.GetProcesses();
            for (int i = 0; i < all.Length; i++)
            {
                Process p = all[i];
                try
                {
                    string pName = p.ProcessName;
                    if (string.Equals(pName, "SSVS", StringComparison.OrdinalIgnoreCase))
                        return p.Id;

                    string fullPath = GetProcessPath(p.Id);
                    if (!string.IsNullOrEmpty(fullPath))
                    {
                        string exeName = Path.GetFileName(fullPath);
                        if (string.Equals(exeName, "SSVS.exe", StringComparison.OrdinalIgnoreCase))
                            return p.Id;
                    }
                }
                catch { }
            }
        }
        catch { }

        return 0;
    }

    static string DeriveStringsPath(int pid)
    {
        // 0. Manual path specified by user or loaded from config
        if (!string.IsNullOrEmpty(manualGamePath))
        {
            try
            {
                string dir = Path.GetDirectoryName(Path.GetFullPath(manualGamePath));
                if (!string.IsNullOrEmpty(dir))
                {
                    string p1 = Path.Combine(dir, "Data", "strings.txt");
                    if (File.Exists(p1)) return p1;
                    string p2 = Path.Combine(dir, "strings.txt");
                    if (File.Exists(p2)) return p2;
                }
            }
            catch { }
        }

        // 1. Dynamic check: Process directory from live PID
        if (pid != 0)
        {
            string exePath = GetProcessPath(pid);
            if (!string.IsNullOrEmpty(exePath))
            {
                string dir = Path.GetDirectoryName(exePath);
                if (!string.IsNullOrEmpty(dir))
                {
                    string p1 = Path.Combine(Path.Combine(dir, "Data"), "strings.txt");
                    if (File.Exists(p1)) return p1;
                    string p2 = Path.Combine(dir, "strings.txt");
                    if (File.Exists(p2)) return p2;
                }
            }
        }

        // 2. Relative search from narrator's own location:
        //    (e.g., if SsvsNarrator is in <GameDir>\mod\ or <GameDir>\ or any subfolder)
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        if (!string.IsNullOrEmpty(baseDir))
        {
            string[] relativeCandidates = new string[]
            {
                Path.Combine(baseDir, "Data", "strings.txt"),
                Path.Combine(baseDir, "..", "Data", "strings.txt"),
                Path.Combine(baseDir, "..", "..", "Data", "strings.txt"),
                Path.Combine(baseDir, "strings.txt"),
                Path.Combine(baseDir, "..", "strings.txt")
            };
            for (int i = 0; i < relativeCandidates.Length; i++)
            {
                try
                {
                    string full = Path.GetFullPath(relativeCandidates[i]);
                    if (File.Exists(full)) return full;
                }
                catch { }
            }
        }

        // 3. Check all fixed / standard Steam library locations across all active drives
        DriveInfo[] drives = DriveInfo.GetDrives();
        for (int i = 0; i < drives.Length; i++)
        {
            try
            {
                DriveInfo d = drives[i];
                if (!d.IsReady) continue;
                string root = d.RootDirectory.FullName;
                string[] steamCandidates = new string[]
                {
                    Path.Combine(root, "Program Files (x86)", "Steam", "steamapps", "common", "SAMURAI SHODOWN V SPECIAL", "Data", "strings.txt"),
                    Path.Combine(root, "Program Files", "Steam", "steamapps", "common", "SAMURAI SHODOWN V SPECIAL", "Data", "strings.txt"),
                    Path.Combine(root, "SteamLibrary", "steamapps", "common", "SAMURAI SHODOWN V SPECIAL", "Data", "strings.txt"),
                    Path.Combine(root, "Steam", "steamapps", "common", "SAMURAI SHODOWN V SPECIAL", "Data", "strings.txt"),
                    Path.Combine(root, "Games", "SteamLibrary", "steamapps", "common", "SAMURAI SHODOWN V SPECIAL", "Data", "strings.txt"),
                    Path.Combine(root, "Jogos", "SteamLibrary", "steamapps", "common", "SAMURAI SHODOWN V SPECIAL", "Data", "strings.txt")
                };
                for (int j = 0; j < steamCandidates.Length; j++)
                {
                    if (File.Exists(steamCandidates[j])) return steamCandidates[j];
                }
            }
            catch { }
        }

        return null;
    }

    static void PreloadAllStrings(string path)
    {
        allStrings.Clear();
        allStrings["pt"] = LoadStrings(path, "pt");
        allStrings["en"] = LoadStrings(path, "en");
        allStrings["es"] = LoadStrings(path, "es");
        allStrings["ja"] = LoadStrings(path, "ja");
    }

    static void SetLanguage(string lang)
    {
        if (lang == null) lang = "pt";
        lang = lang.ToLowerInvariant();
        if (lang != "pt" && lang != "en" && lang != "es" && lang != "ja") lang = "pt";
        currentLang = lang;
        if (allStrings.ContainsKey(lang))
            stringMap = allStrings[lang];
        else if (cachedStringsPath != null)
            stringMap = LoadStrings(cachedStringsPath, lang);
    }

    // Data\strings.txt: UTF-16LE, tab-separated, header on line 0:
    //   default_en  category  en  pt  es  ja
    // col0 = key, col2 = en, col3 = pt, col4 = es, col5 = ja.
    static Dictionary<string, string> LoadStrings(string path, string lang = "pt")
    {
        Dictionary<string, string> map = new Dictionary<string, string>();
        if (path == null || !File.Exists(path)) return map;

        string text;
        try { text = File.ReadAllText(path, Encoding.Unicode); }
        catch { return map; }

        string[] lines = text.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        int langCol = 3; // pt default
        if (lang == "en") langCol = 2;
        else if (lang == "es") langCol = 4;
        else if (lang == "ja") langCol = 5;

        for (int i = 0; i < lines.Length; i++)
        {
            if (i == 0) continue; // header
            string[] c = lines[i].Split('\t');
            if (c.Length < 3) continue;
            string key = c[0].Trim();
            if (key.Length == 0) continue;
            string disp = "";
            if (langCol < c.Length && c[langCol].Trim().Length > 0)
                disp = c[langCol].Trim();
            else if (c.Length > 2 && c[2].Trim().Length > 0)
                disp = c[2].Trim();
            else
                disp = key;
            if (!map.ContainsKey(key)) map[key] = disp;
        }
        return map;
    }

    static string FormatCommandText(string cmd)
    {
        if (string.IsNullOrEmpty(cmd)) return "";
        string s = cmd.Replace('\r', ' ').Replace('\n', ' ').Trim();

        if (currentLang == "en")
        {
            s = s.Replace("→ ↘ ↓ ↙ ←→", "forward, half circle back, forward, ");
            s = s.Replace("→↘↓↙←→", "forward, half circle back, forward, ");
            s = s.Replace("↓ ↘ →", "down, down-forward, forward, ");
            s = s.Replace("↓↘→", "down, down-forward, forward, ");
            s = s.Replace("↓ ↙ ←", "down, down-back, back, ");
            s = s.Replace("↓↙←", "down, down-back, back, ");
            s = s.Replace("→↓ ↘", "forward, down, down-forward, ");
            s = s.Replace("→ ↓ ↘", "forward, down, down-forward, ");
            s = s.Replace("←↓ ↙", "back, down, down-back, ");
            s = s.Replace("← ↓ ↙", "back, down, down-back, ");

            s = s.Replace("↑", "up ");
            s = s.Replace("↓", "down ");
            s = s.Replace("←", "back ");
            s = s.Replace("→", "forward ");
            s = s.Replace("↘", "down-forward ");
            s = s.Replace("↙", "down-back ");
            s = s.Replace("↗", "up-forward ");
            s = s.Replace("↖", "up-back ");

            s = s.Replace("+ BCD", "plus Overkill");
            s = s.Replace("+ CD", "plus Rage");
            s = s.Replace("+ BC", "plus Throw");
            s = s.Replace("+ AB", "plus Heavy Slash");
            s = s.Replace("+ S", "plus Slash");
            s = s.Replace("+ A", "plus Light Slash");
            s = s.Replace("+ B", "plus Medium Slash");
            s = s.Replace("+ C", "plus Kick");
            s = s.Replace("+ D", "plus Special");
            s = s.Replace("+", "plus ");
        }
        else if (currentLang == "es")
        {
            s = s.Replace("→ ↘ ↓ ↙ ←→", "adelante, media luna atrás, adelante, ");
            s = s.Replace("→↘↓↙←→", "adelante, media luna atrás, adelante, ");
            s = s.Replace("↓ ↘ →", "abajo, diagonal adelante, adelante, ");
            s = s.Replace("↓↘→", "abajo, diagonal adelante, adelante, ");
            s = s.Replace("↓ ↙ ←", "abajo, diagonal atrás, atrás, ");
            s = s.Replace("↓↙←", "abajo, diagonal atrás, atrás, ");
            s = s.Replace("→↓ ↘", "adelante, abajo, diagonal adelante, ");
            s = s.Replace("→ ↓ ↘", "adelante, abajo, diagonal adelante, ");
            s = s.Replace("←↓ ↙", "atrás, abajo, diagonal atrás, ");
            s = s.Replace("← ↓ ↙", "atrás, abajo, diagonal atrás, ");

            s = s.Replace("↑", "arriba ");
            s = s.Replace("↓", "abajo ");
            s = s.Replace("←", "atrás ");
            s = s.Replace("→", "adelante ");
            s = s.Replace("↘", "diagonal abajo adelante ");
            s = s.Replace("↙", "diagonal abajo atrás ");
            s = s.Replace("↗", "diagonal arriba adelante ");
            s = s.Replace("↖", "diagonal arriba atrás ");

            s = s.Replace("+ BCD", "más Golpe Fatal");
            s = s.Replace("+ CD", "más Furia");
            s = s.Replace("+ BC", "más Agarre");
            s = s.Replace("+ AB", "más Corte Fuerte");
            s = s.Replace("+ S", "más Corte");
            s = s.Replace("+ A", "más Corte Débil");
            s = s.Replace("+ B", "mais Corte Medio");
            s = s.Replace("+ C", "más Patada");
            s = s.Replace("+ D", "más Especial");
            s = s.Replace("+", "más ");
        }
        else if (currentLang == "ja")
        {
            s = s.Replace("→ ↘ ↓ ↙ ←→", "前、半回転後ろ、前、");
            s = s.Replace("→↘↓↙←→", "前、半回転後ろ、前、");
            s = s.Replace("↓ ↘ →", "下、斜め前、前、");
            s = s.Replace("↓↘→", "下、斜め前、前、");
            s = s.Replace("↓ ↙ ←", "下、斜め後ろ、後ろ、");
            s = s.Replace("↓↙←", "下、斜め後ろ、後ろ、");
            s = s.Replace("→↓ ↘", "前、下、斜め前、");
            s = s.Replace("→ ↓ ↘", "前、下、斜め前、");
            s = s.Replace("←↓ ↙", "後ろ、下、斜め後ろ、");
            s = s.Replace("← ↓ ↙", "後ろ、下、斜め後ろ、");

            s = s.Replace("↑", "上 ");
            s = s.Replace("↓", "下 ");
            s = s.Replace("←", "後ろ ");
            s = s.Replace("→", "前 ");
            s = s.Replace("↘", "斜め下前 ");
            s = s.Replace("↙", "斜め下後ろ ");
            s = s.Replace("↗", "斜め上前 ");
            s = s.Replace("↖", "斜め上後ろ ");

            s = s.Replace("+ BCD", "+ 絶命奥義");
            s = s.Replace("+ CD", "+ 怒り爆発");
            s = s.Replace("+ BC", "+ 投げ");
            s = s.Replace("+ AB", "+ 強斬り");
            s = s.Replace("+ S", "+ 斬り");
            s = s.Replace("+ A", "+ 弱斬り");
            s = s.Replace("+ B", "+ 中斬り");
            s = s.Replace("+ C", "+ 蹴り");
            s = s.Replace("+ D", "+ 特殊");
        }
        else // default Portuguese
        {
            s = s.Replace("→ ↘ ↓ ↙ ←→", "frente, meia lua trás, frente, ");
            s = s.Replace("→↘↓↙←→", "frente, meia lua trás, frente, ");
            s = s.Replace("↓ ↘ →", "baixo, diagonal frente, frente, ");
            s = s.Replace("↓↘→", "baixo, diagonal frente, frente, ");
            s = s.Replace("↓ ↙ ←", "baixo, diagonal trás, trás, ");
            s = s.Replace("↓↙←", "baixo, diagonal trás, trás, ");
            s = s.Replace("→↓ ↘", "frente, baixo, diagonal frente, ");
            s = s.Replace("→ ↓ ↘", "frente, baixo, diagonal frente, ");
            s = s.Replace("←↓ ↙", "trás, baixo, diagonal trás, ");
            s = s.Replace("← ↓ ↙", "trás, baixo, diagonal trás, ");

            s = s.Replace("↑", "cima ");
            s = s.Replace("↓", "baixo ");
            s = s.Replace("←", "trás ");
            s = s.Replace("→", "frente ");
            s = s.Replace("↘", "diagonal baixo frente ");
            s = s.Replace("↙", "diagonal baixo trás ");
            s = s.Replace("↗", "diagonal cima frente ");
            s = s.Replace("↖", "diagonal cima trás ");

            s = s.Replace("+ BCD", "mais Golpe Fatal");
            s = s.Replace("+ CD", "mais Fúria");
            s = s.Replace("+ BC", "mais Arremesso");
            s = s.Replace("+ AB", "mais Corte Forte");
            s = s.Replace("+ S", "mais Golpe de Espada");
            s = s.Replace("+ A", "mais Corte Fraco");
            s = s.Replace("+ B", "mais Corte Médio");
            s = s.Replace("+ C", "mais Chute");
            s = s.Replace("+ D", "mais Especial");
            s = s.Replace("+", "mais ");
        }

        while (s.Contains("  ")) s = s.Replace("  ", " ");
        s = s.Replace(" ,", ",");
        return s.Trim();
    }

    // ---- process memory helpers ----

    static byte[] ReadBytes(IntPtr h, long addr, int len)
    {
        byte[] buf = new byte[len];
        IntPtr read;
        if (!ReadProcessMemory(h, new IntPtr(addr), buf, new IntPtr(len), out read)) return null;
        if (read.ToInt64() < len) return null;
        return buf;
    }

    static uint ReadU32(IntPtr h, long addr)
    {
        byte[] b = ReadBytes(h, addr, 4);
        if (b == null) return 0;
        return (uint)(b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24));
    }

    static ushort ReadU16(IntPtr h, long addr)
    {
        byte[] b = ReadBytes(h, addr, 2);
        if (b == null) return 0;
        return (ushort)(b[0] | (b[1] << 8));
    }

    static byte ReadU8(IntPtr h, long addr)
    {
        byte[] b = ReadBytes(h, addr, 1);
        if (b == null) return 0;
        return b[0];
    }

    static string ReadCString(IntPtr h, long addr, int max)
    {
        if (addr <= 0x1000) return "";
        List<byte> raw = new List<byte>(max > 128 ? 128 : max);
        byte[] chunk = new byte[64];
        int read = 0;
        while (read < max)
        {
            int want = Math.Min(64, max - read);
            IntPtr got;
            if (!ReadProcessMemory(h, new IntPtr(addr + read), chunk, new IntPtr(want), out got) || got.ToInt64() <= 0)
            {
                byte[] one = ReadBytes(h, addr + read, 1);
                if (one == null || one[0] == 0) break;
                raw.Add(one[0]);
                read += 1;
                continue;
            }
            int n = (int)got.ToInt64();
            bool term = false;
            for (int i = 0; i < n; i++)
            {
                if (chunk[i] == 0) { term = true; break; }
                raw.Add(chunk[i]);
            }
            if (term) break;
            read += n;
        }
        try { return Encoding.UTF8.GetString(raw.ToArray()); }
        catch { return Encoding.Default.GetString(raw.ToArray()); }
    }

    // ---- manager discovery ----

    static uint lastScanTick = 0;

    static long GetManager(IntPtr h)
    {
        if (mgr != 0 && ValidateManager(h, mgr)) return mgr;

        // 0. Priority: Dynamically detected pointer from Auto-Scan
        if (dynamicMenuManagerPtr != 0)
        {
            uint candDyn = ReadU32(h, dynamicMenuManagerPtr);
            if (candDyn >= 0x10000 && candDyn <= 0x7fff0000 && ValidateManager(h, candDyn))
            {
                mgr = candDyn;
                return mgr;
            }
        }

        // Fast static check 1: Master MenuManager instance pointer stored at 0x005F0688
        long p1 = ResolveAddr(0x005F0688);
        uint cand1 = ReadU32(h, p1);
        if (cand1 >= 0x10000 && cand1 <= 0x7fff0000 && ValidateManager(h, cand1))
        {
            mgr = cand1;
            return mgr;
        }

        // Fast static check 2: Master UI Controller / Menu Interface stored at 0x005E85BC
        long p2 = ResolveAddr(0x005E85BC);
        uint cand2 = ReadU32(h, p2);
        if (cand2 >= 0x10000 && cand2 <= 0x7fff0000 && ValidateManager(h, cand2))
        {
            mgr = cand2;
            return mgr;
        }

        // Fast static check 3: Alternative state pointer at 0x005F03D4
        long p3 = ResolveAddr(0x005F03D4);
        uint cand3 = ReadU32(h, p3);
        if (cand3 >= 0x10000 && cand3 <= 0x7fff0000 && ValidateManager(h, cand3))
        {
            mgr = cand3;
            return mgr;
        }

        // Throttle fallback memory scan to at most once every 1000ms
        uint now = (uint)Environment.TickCount;
        if (now - lastScanTick < 1000) return 0;
        lastScanTick = now;

        mgr = ScanForManager(h);
        return mgr;
    }

    static long ScanForManager(IntPtr h)
    {
        uint targetVt = dynamicMenuManagerVtable != 0 ? dynamicMenuManagerVtable : (uint)ResolveAddr(MENU_MANAGER_VTABLE);
        byte[] pat = new byte[4];
        pat[0] = (byte)(targetVt & 0xff);
        pat[1] = (byte)((targetVt >> 8) & 0xff);
        pat[2] = (byte)((targetVt >> 16) & 0xff);
        pat[3] = (byte)((targetVt >> 24) & 0xff);

        MEMORY_BASIC_INFORMATION mbi;
        IntPtr mbiSize = new IntPtr(Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
        long addr = 0x10000;
        const long MAX = 0x7fff0000L;

        while (addr < MAX)
        {
            if (VirtualQueryEx(h, new IntPtr(addr), out mbi, mbiSize) == IntPtr.Zero) break;
            long baseAddr = mbi.BaseAddress.ToInt64();
            long regionSize = mbi.RegionSize.ToInt64();
            if (regionSize <= 0) break;

            bool writable = mbi.State == MEM_COMMIT &&
                (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_WRITECOPY ||
                 mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY);

            if (writable)
            {
                long found = ScanRegion(h, baseAddr, regionSize, pat);
                if (found != 0) return found;
            }
            addr = baseAddr + regionSize;
        }
        return 0;
    }

    static long ScanRegion(IntPtr h, long baseAddr, long size, byte[] pat)
    {
        long off = 0;
        while (off < size)
        {
            long remain = size - off;
            int want = (int)Math.Min((long)CHUNK, remain);
            int readLen = want;
            if (off + want < size) readLen = want + 3; // overlap for cross-boundary match

            byte[] buf = new byte[readLen];
            IntPtr got;
            if (!ReadProcessMemory(h, new IntPtr(baseAddr + off), buf, new IntPtr(readLen), out got) || got.ToInt64() < 4)
            {
                off += want;
                continue;
            }
            int n = (int)got.ToInt64();
            for (int i = 0; i + 4 <= n; i += 4)
            {
                if (buf[i] == pat[0] && buf[i + 1] == pat[1] && buf[i + 2] == pat[2] && buf[i + 3] == pat[3])
                {
                    long cand = baseAddr + off + i;
                    if (ValidateManager(h, cand)) return cand;
                }
            }
            off += want;
        }
        return 0;
    }

    static bool ValidateManager(IntPtr h, long cand)
    {
        if (cand <= 0x1000 || cand > 0x7fff0000) return false;
        uint vtMgr = ReadU32(h, cand);
        uint expectedVt = dynamicMenuManagerVtable != 0 ? dynamicMenuManagerVtable : (uint)ResolveAddr(MENU_MANAGER_VTABLE);
        if (vtMgr == expectedVt) return true;

        long rLo = ResolveAddr(RDATA_LO);
        long rHi = ResolveAddr(RDATA_HI);
        if (vtMgr >= rLo && vtMgr <= rHi)
        {
            uint menu = ReadU32(h, cand + OFF_MGR_MENU);
            if (menu == 0) return true; // valid manager even when no menu is open yet!
            if (menu >= 0x10000 && menu <= 0x7fff0000)
            {
                uint vt = ReadU32(h, menu);
                if (vt >= rLo && vt <= rHi) return true;
            }
        }
        return false;
    }

    static int ReadSelectedIndex(IntPtr h, long menu)
    {
        uint namePtr = ReadU32(h, menu + OFF_MENU_SELNAME);
        string s = ReadCString(h, namePtr, 32);
        if (s.Length >= 5 && s.Substring(0, 4) == "line")
        {
            int n;
            if (int.TryParse(s.Substring(4), out n))
            {
                int i = n - 1;
                if (i >= 0) return i;
            }
        }
        uint raw = ReadU32(h, menu + OFF_MENU_SELIDX);
        if (raw < 1000) return (int)raw;
        return -1;
    }

    // A label key must be a non-empty run of printable ASCII. Menu keys are plain identifiers
    // (e.g. "local_game"), so this cheaply rejects RTTI blobs / binary tables that happen to
    // follow a label array in .rdata.
    static bool IsPrintableKey(string s)
    {
        if (s == null || s.Length == 0) return false;
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (c < 32 || c > 126) return false;
        }
        return true;
    }

    // Derive an item count by walking the inherited label array (menu + 0x6c) until an entry
    // stops looking like a key pointer. Module keys live in .rdata and point at printable text,
    // so the first non-conforming slot marks the end of the menu's items. Returns -1 if the
    // array doesn't look usable at all.
    static int DeriveCount(IntPtr h, uint arr)
    {
        int n = 0;
        while (n < 256)
        {
            uint kp = ReadU32(h, (long)arr + (long)n * 4);
            if (kp < RDATA_LO || kp > RDATA_HI) break;
            if (!IsPrintableKey(ReadCString(h, kp, 64))) break;
            n++;
        }
        return n;
    }

    // ---- menu name map ----
    static string MenuName(uint vt)
    {
        uint origVt = (uint)(vt - baseDelta);
        switch (origVt)
        {
            case 0x4b7fb4: return (currentLang == "en") ? "Main Menu" : (currentLang == "es") ? "Menú Principal" : (currentLang == "ja") ? "メインメニュー" : "Menu Principal";
            case 0x4b807c: return (currentLang == "en") ? "Multiplayer" : (currentLang == "es") ? "Multijugador" : (currentLang == "ja") ? "マルチプレイヤー" : "Multijogador";
            case 0x4b8194: return (currentLang == "en") ? "Online Match" : (currentLang == "es") ? "Partida Online" : (currentLang == "ja") ? "オンライン対戦" : "Partida Online";
            case 0x4b7c54: return (currentLang == "en") ? "Lobby" : (currentLang == "es") ? "Lobby" : (currentLang == "ja") ? "ロビー" : "Lobby";
            case 0x4b8a8c: return (currentLang == "en") ? "Room" : (currentLang == "es") ? "Sala" : (currentLang == "ja") ? "ルーム" : "Sala";
            case 0x4b73a4: return (currentLang == "en") ? "Gallery" : (currentLang == "es") ? "Galería" : (currentLang == "ja") ? "ギャラリー" : "Galeria";
            case 0x4b7474: return (currentLang == "en") ? "Art Viewer" : (currentLang == "es") ? "Visor de Arte" : (currentLang == "ja") ? "アートビューアー" : "Visualizador de Arte";
            case 0x4b79cc: return (currentLang == "en") ? "Leaderboards" : (currentLang == "es") ? "Marcadores" : (currentLang == "ja") ? "リーダーボード" : "Placares de Líderes";
            case 0x4b8e24: return (currentLang == "en") ? "Trophies and Achievements" : (currentLang == "es") ? "Trofeos y Logros" : (currentLang == "ja") ? "トロフィー" : "Troféus e Conquistas";
            case 0x4b8264: return (currentLang == "en") ? "Options" : (currentLang == "es") ? "Opciones" : (currentLang == "ja") ? "オプション" : "Opções";
            case 0x4b8c64: return (currentLang == "en") ? "Settings" : (currentLang == "es") ? "Ajustes" : (currentLang == "ja") ? "設定" : "Configurações";
            case 0x4b8d8c: return (currentLang == "en") ? "System Settings" : (currentLang == "es") ? "Ajustes del Sistema" : (currentLang == "ja") ? "システム設定" : "Configurações do Sistema";
            case 0x4b7614: return (currentLang == "en") ? "Game Settings" : (currentLang == "es") ? "Ajustes de Juego" : (currentLang == "ja") ? "ゲーム設定" : "Configurações do Jogo";
            case 0x4b729c: return (currentLang == "en") ? "Display Settings" : (currentLang == "es") ? "Ajustes de Pantalla" : (currentLang == "ja") ? "画面設定" : "Configurações de Tela";
            case 0x4b919c: return (currentLang == "en") ? "Volume Settings" : (currentLang == "es") ? "Ajustes de Volumen" : (currentLang == "ja") ? "音量設定" : "Configurações de Volume";
            case 0x4b6dc4: return (currentLang == "en") ? "Controls" : (currentLang == "es") ? "Controles" : (currentLang == "ja") ? "操作設定" : "Configurações de Controle";
            case 0x4b786c: return (currentLang == "en") ? "Room Settings" : (currentLang == "es") ? "Ajustes de Sala" : (currentLang == "ja") ? "ルーム設定" : "Configurações da Sala";
            case 0x4b76b4: return (currentLang == "en") ? "Hidden Characters" : (currentLang == "es") ? "Personajes Secretos" : (currentLang == "ja") ? "隠しキャラクター" : "Personagens Secretos";
            case 0x4b6ac4: return (currentLang == "en") ? "Command List" : (currentLang == "es") ? "Lista de Movimientos" : (currentLang == "ja") ? "技表" : "Lista de Golpes";
            case 0x4b7094: return (currentLang == "en") ? "Credits" : (currentLang == "es") ? "Créditos" : (currentLang == "ja") ? "クレジット" : "Créditos";
            case 0x4b8334: return (currentLang == "en") ? "Pause Menu" : (currentLang == "es") ? "Menú de Pausa" : (currentLang == "ja") ? "ポーズメニュー" : "Menu de Pausa";
            case 0x4b7914: return (currentLang == "en") ? "Match Options" : (currentLang == "es") ? "Opciones de Partida" : (currentLang == "ja") ? "試合オプション" : "Opções da Partida";
            case 0x4b8424: return (currentLang == "en") ? "Match" : (currentLang == "es") ? "Partida" : (currentLang == "ja") ? "対戦" : "Partida";
            case 0x4b84a4: return (currentLang == "en") ? "Information" : (currentLang == "es") ? "Información" : (currentLang == "ja") ? "情報" : "Informação";
            case 0x4b8514: return (currentLang == "en") ? "Confirmation" : (currentLang == "es") ? "Confirmación" : (currentLang == "ja") ? "確認" : "Confirmação";
            case 0x4b8684: return (currentLang == "en") ? "Ranking" : (currentLang == "es") ? "Clasificación" : (currentLang == "ja") ? "ランキング" : "Classificação";
            case 0x4b9bb4: return (currentLang == "en") ? "Practice Menu" : (currentLang == "es") ? "Menú de Práctica" : (currentLang == "ja") ? "プラクティスメニュー" : "Menu de Treino";
            case 0x4b9a3c: return (currentLang == "en") ? "Overlay" : (currentLang == "es") ? "Superposición" : (currentLang == "ja") ? "オーバーレイ" : "Sobreposição";
            default: return (currentLang == "en") ? "Menu" : (currentLang == "es") ? "Menú" : (currentLang == "ja") ? "メニュー" : "Menu";
        }
    }

    // ---- specialized trophy descriptions ----
    static readonly string[] TrophyNames = new string[]
    {
        "Haohmaru Completo",
        "Nakoruru Completo",
        "Hanzo Completo",
        "Galford Completo",
        "Ukyo Completo",
        "Kyoshiro Completo",
        "Genjuro Completo",
        "Basara Completo",
        "Jubei Completo",
        "Charlotte Completo",
        "Yoshitora Completo",
        "Kazuki Completo",
        "Sogetsu Completo",
        "Rera Completo",
        "4 Chefes Derrotados",
        "Espadachim (5 Vitórias Online)",
        "Mestre da Espada (20 Vitórias Online)",
        "Santo da Espada (Sequência de 10 Vitórias Online)"
    };

    static readonly string[] LeaderboardModes = new string[]
    {
        "Modo História",
        "Ranking de Vitórias",
        "Haohmaru", "Nakoruru", "Rimururu", "Hanzo", "Galford", "Kyoshiro",
        "Ukyo", "Genjuro", "Basara", "Shizumaru", "Gaira", "Amakusa",
        "Jubei", "Zankuro", "Charlotte", "Tam Tam", "Kazuki", "Sogetsu",
        "Rasetsumaru", "Rera", "Enja", "Suija", "Yoshitora", "Yunfei",
        "Mina", "Kusaregedo", "Gaoh", "Mizuki"
    };

    static string GetLeaderboardModeName(int idx)
    {
        if (idx == 0) return (currentLang == "en") ? "Story Mode" : (currentLang == "es") ? "Modo Historia" : (currentLang == "ja") ? "ストーリーモード" : "Modo História";
        if (idx == 1) return (currentLang == "en") ? "Win Ranking" : (currentLang == "es") ? "Clasificación de Victorias" : (currentLang == "ja") ? "勝利数ランキング" : "Ranking de Vitórias";
        if (idx >= 0 && idx < LeaderboardModes.Length) return LeaderboardModes[idx];
        return (currentLang == "en") ? ("Board " + (idx + 1)) : (currentLang == "es") ? ("Marcador " + (idx + 1)) : (currentLang == "ja") ? ("ボード " + (idx + 1)) : ("Placar " + (idx + 1));
    }

    static readonly string[] ControlActionKeys = new string[]
    {
        "Preset", "Default", "Up", "Down", "Left", "Right", "Start",
        "A", "B", "C", "D", "AB", "BC", "CD", "ABC", "BCD", "Coin"
    };

    static string GetControlActionName(int row)
    {
        if (currentLang == "en")
        {
            switch (row)
            {
                case 0: return "Preset";
                case 1: return "Reset to Default";
                case 2: return "Up";
                case 3: return "Down";
                case 4: return "Left";
                case 5: return "Right";
                case 6: return "Start / Pause";
                case 7: return "Light Slash (A)";
                case 8: return "Medium Slash (B)";
                case 9: return "Kick (C)";
                case 10: return "Special / Dodge (D)";
                case 11: return "Heavy Slash (A+B)";
                case 12: return "Throw (B+C)";
                case 13: return "Rage Explosion (C+D)";
                case 14: return "Honorable Suicide (A+B+C)";
                case 15: return "Overkill (B+C+D)";
                case 16: return "Insert Coin / Select";
                default: return "Control " + (row + 1);
            }
        }
        else if (currentLang == "es")
        {
            switch (row)
            {
                case 0: return "Predeterminado";
                case 1: return "Restaurar";
                case 2: return "Arriba";
                case 3: return "Abajo";
                case 4: return "Izquierda";
                case 5: return "Derecha";
                case 6: return "Start / Pausa";
                case 7: return "Corte Débil (A)";
                case 8: return "Corte Medio (B)";
                case 9: return "Patada (C)";
                case 10: return "Especial / Esquiva (D)";
                case 11: return "Corte Fuerte (A+B)";
                case 12: return "Agarre (B+C)";
                case 13: return "Explosión de Furia (C+D)";
                case 14: return "Suicidio Honorable (A+B+C)";
                case 15: return "Golpe Fatal Overkill (B+C+D)";
                case 16: return "Ficha / Seleccionar";
                default: return "Control " + (row + 1);
            }
        }
        else if (currentLang == "ja")
        {
            switch (row)
            {
                case 0: return "プリセット";
                case 1: return "初期設定に戻す";
                case 2: return "上";
                case 3: return "下";
                case 4: return "左";
                case 5: return "右";
                case 6: return "スタート / 一時停止";
                case 7: return "弱斬り (A)";
                case 8: return "中斬り (B)";
                case 9: return "蹴り (C)";
                case 10: return "特殊 (D)";
                case 11: return "強斬り (A+B)";
                case 12: return "投げ (B+C)";
                case 13: return "怒り爆発 (C+D)";
                case 14: return "自決 (A+B+C)";
                case 15: return "絶命奥義 (B+C+D)";
                case 16: return "コイン / セレクト";
                default: return "操作 " + (row + 1);
            }
        }
        else
        {
            switch (row)
            {
                case 0: return "Predefinição";
                case 1: return "Restaurar Padrão";
                case 2: return "Cima";
                case 3: return "Baixo";
                case 4: return "Esquerda";
                case 5: return "Direita";
                case 6: return "Start / Pausa";
                case 7: return "Corte Fraco (A)";
                case 8: return "Corte Médio (B)";
                case 9: return "Chute (C)";
                case 10: return "Especial / Esquiva (D)";
                case 11: return "Corte Forte (A+B)";
                case 12: return "Arremesso (B+C)";
                case 13: return "Explosão de Fúria (C+D)";
                case 14: return "Suicídio Honroso (A+B+C)";
                case 15: return "Golpe Fatal Overkill (B+C+D)";
                case 16: return "Ficha / Selecionar";
                default: return "Controle " + (row + 1);
            }
        }
    }

    // ---- Neo-Geo 68k Arcade game state ----
    const long NEO_BANK_TABLE = 0x012ea754;
    static uint ramBase = 0;
    static int lastP1Char = -1;
    static int lastP2Char = -1;
    static int lastP1Style = -1;
    static int lastP2Style = -1;
    static int lastP1Lock = -1;
    static int lastStage = -1;
    static uint lastBg = 0xFFFFFFFF;
    static bool announcedCharSelect = false;

    // Mapeamento exato de cada um dos 29 slots de cursor do jogo (c1_obj + 0xc2)
    // Descoberto diretamente na ROM do Neo-Geo (tabela de conversão 0x1BCA2, navegação 0x1BBB8 e coordenadas 0x1BC2C):
    static readonly string[] CharacterNames = new string[]
    {
        /* Slot 00 - CharID 00 (Linha 1, Coluna 3) */ "Haohmaru",
        /* Slot 01 - CharID 01 (Linha 2, Coluna 3) */ "Nakoruru",
        /* Slot 02 - CharID 02 (Linha 2, Coluna 9) */ "Rimururu",
        /* Slot 03 - CharID 03 (Linha 3, Coluna 9) */ "Hattori Hanzo",
        /* Slot 04 - CharID 04 (Linha 3, Coluna 4) */ "Galford D. Weller",
        /* Slot 05 - CharID 05 (Linha 3, Coluna 7) */ "Kyoshiro Senryo",
        /* Slot 06 - CharID 06 (Linha 1, Coluna 9) */ "Ukyo Tachibana",
        /* Slot 07 - CharID 07 (Linha 1, Coluna 4) */ "Genjuro Kibagami",
        /* Slot 08 - CharID 08 (Linha 2, Coluna 6) */ "Basara Kubikiri",
        /* Slot 09 - CharID 09 (Linha 1, Coluna 5) */ "Shizumaru Hisame",
        /* Slot 10 - CharID 10 (Linha 1, Coluna 8) */ "Gaira Caffeine",
        /* Slot 11 - CharID 12 (Linha 3, Coluna 8) */ "Jubei Yagyu",
        /* Slot 12 - CharID 14 (Linha 3, Coluna 5) */ "Charlotte Christine de Colde",
        /* Slot 13 - CharID 15 (Linha 2, Coluna 7) */ "Tam Tam",
        /* Slot 14 - CharID 16 (Linha 1, Coluna 6) */ "Kazuki Kazama",
        /* Slot 15 - CharID 17 (Linha 1, Coluna 7) */ "Sogetsu Kazama",
        /* Slot 16 - CharID 18 (Linha 2, Coluna 8) */ "Rasetsumaru",
        /* Slot 17 - CharID 19 (Linha 2, Coluna 4) */ "Rera",
        /* Slot 18 - CharID 20 (Linha 3, Coluna 1) */ "Enja",
        /* Slot 19 - CharID 21 (Linha 3, Coluna 3) */ "Suija",
        /* Slot 20 - CharID 22 (Linha 1, Coluna 1) */ "Yoshitora Tokugawa",
        /* Slot 21 - CharID 23 (Linha 2, Coluna 5) */ "Liu Yunfei",
        /* Slot 22 - CharID 24 (Linha 2, Coluna 1) */ "Mina Majikina",
        /* Slot 23 - CharID 25 (Linha 3, Coluna 6) */ "Yokai Kusaregedo",
        /* Slot 24 - CharID 32 (Secreto / Chefe)   */ "Mizuki Rashojin",
        /* Slot 25 - CharID 11 (Linha 3, Coluna 2) */ "Shiro Tokisada Amakusa",
        /* Slot 26 - CharID 13 (Linha 2, Coluna 2) */ "Zankuro Minazuki",
        /* Slot 27 - CharID 27 (Secreto / 2x Baixo)*/ "Mizuki Rashojin",
        /* Slot 28 - CharID 26 (Linha 1, Coluna 2) */ "Gaoh (Gaoh Kyougoku Hinowa no Kami)"
    };

    static readonly byte[] SlotToCharIdTable = new byte[]
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0C, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x20, 0x0B, 0x0D, 0x1B, 0x1A
    };

    static int CharIdToSlot(byte charId)
    {
        for (int i = 0; i < SlotToCharIdTable.Length; i++)
        {
            if (SlotToCharIdTable[i] == charId) return i;
        }
        return -1;
    }

    static string GetStageName(int stage)
    {
        string pfx = (currentLang == "en") ? "Stage " : (currentLang == "es") ? "Escenario " : (currentLang == "ja") ? "ステージ " : "Cenário ";
        if (stage >= 0 && stage <= 5) return pfx + (stage + 1);
        if (stage == 6) return (currentLang == "en") ? "Amakusa Stage" : (currentLang == "es") ? "Escenario Amakusa" : (currentLang == "ja") ? "天草ステージ" : "Cenário Amakusa";
        if (stage == 7) return (currentLang == "en") ? "Zankuro Stage" : (currentLang == "es") ? "Escenario Zankuro" : (currentLang == "ja") ? "斬紅郎ステージ" : "Cenário Zankuro";
        if (stage == 8) return (currentLang == "en") ? "Gaoh Stage" : (currentLang == "es") ? "Escenario Gaoh" : (currentLang == "ja") ? "我旺ステージ" : "Cenário Gaoh";
        if (stage == 9) return (currentLang == "en") ? "Final Mizuki Stage" : (currentLang == "es") ? "Escenario Final Mizuki" : (currentLang == "ja") ? "最終水姫ステージ" : "Cenário Final Mizuki";
        return pfx + (stage + 1);
    }

    static string GetBackgroundName(uint bg)
    {
        uint id = bg & 0xFFFF;
        if (currentLang == "en")
        {
            switch (id)
            {
                case 0x0000: return "Pier (Late Afternoon)";
                case 0x0001: return "Pier (Night)";
                case 0x0002: return "Bridge with People";
                case 0x0003: return "Bridge with Dog";
                case 0x0004: return "Shrine";
                case 0x0005: return "Shrine (Night)";
                case 0x0008: return "Obama Beach";
                case 0x0009: return "Dohsaki (Zankuro)";
                case 0x000A: return "Kusenbutake (Amakusa)";
                case 0x000B: return "Yoshitora Mansion";
                case 0x000C: return "Mountains";
                case 0x000D: return "Mina Shrine (Night)";
                case 0x000E: return "Graveyard";
                case 0x0012: return "Aftermath (Gaoh)";
                case 0x0013: return "Evil Shrine of Mizuki";
                default: return null;
            }
        }
        else if (currentLang == "es")
        {
            switch (id)
            {
                case 0x0000: return "Muelle (Atardecer)";
                case 0x0001: return "Muelle (Noche)";
                case 0x0002: return "Puente con Gente";
                case 0x0003: return "Puente con Perro";
                case 0x0004: return "En el Templo";
                case 0x0005: return "En el Templo (Noche)";
                case 0x0008: return "Playa de Obama";
                case 0x0009: return "Dohsaki (Zankuro)";
                case 0x000A: return "Kusenbutake (Amakusa)";
                case 0x000B: return "Mansión Yoshitora";
                case 0x000C: return "Montañas";
                case 0x000D: return "Templo de Mina (Noche)";
                case 0x000E: return "Cementerio";
                case 0x0012: return "Posguerra (Gaoh)";
                case 0x0013: return "Templo del Mal de Mizuki";
                default: return null;
            }
        }
        else if (currentLang == "ja")
        {
            switch (id)
            {
                case 0x0000: return "波止場 (夕方)";
                case 0x0001: return "波止場 (夜)";
                case 0x0002: return "橋 (人々)";
                case 0x0003: return "橋 (犬)";
                case 0x0004: return "神社";
                case 0x0005: return "神社 (夜)";
                case 0x0008: return "小浜海岸";
                case 0x0009: return "堂崎 (斬紅郎)";
                case 0x000A: return "九千部岳 (天草)";
                case 0x000B: return "慶寅邸";
                case 0x000C: return "連山";
                case 0x000D: return "ミナ神社 (夜)";
                case 0x000E: return "墓場";
                case 0x0012: return "戦跡 (我旺)";
                case 0x0013: return "恐山 (水姫)";
                default: return null;
            }
        }
        else
        {
            switch (id)
            {
                case 0x0000: return "Cais (Fim de Tarde)";
                case 0x0001: return "Cais (Noite)";
                case 0x0002: return "Ponte com Pessoas";
                case 0x0003: return "Ponte com Cachorro";
                case 0x0004: return "No Templo";
                case 0x0005: return "No Templo (Noite)";
                case 0x0008: return "Praia de Obama";
                case 0x0009: return "Dohsaki (Zankuro)";
                case 0x000A: return "Kusenbutake (Amakusa)";
                case 0x000B: return "Mansão Yoshitora";
                case 0x000C: return "Montanhas";
                case 0x000D: return "Templo de Mina (Noite)";
                case 0x000E: return "Cemitério";
                case 0x0012: return "Pós-Guerra (Gaoh)";
                case 0x0013: return "Templo do Mal de Mizuki";
                default: return null;
            }
        }
    }

    static int FindCursorObject(IntPtr h, long ramBase, string targetTag)
    {
        ushort headOffset = ReadU16(h, ramBase + 4);
        long curr = 0x100000 + headOffset;
        int count = 0;
        while (curr >= 0x100000 && curr <= 0x10ffff && (curr & 1) == 0 && count < 64)
        {
            byte[] chunk = ReadBytes(h, ramBase + (curr & 0xffff) + 0x10, 16);
            if (chunk != null && chunk.Length >= 8)
            {
                char[] tagChars = new char[8];
                for (int i = 0; i < 8; i++) tagChars[i] = (char)chunk[i ^ 1];
                string tag = new string(tagChars);
                if (tag.StartsWith(targetTag))
                {
                    return (int)(curr & 0xffff);
                }
            }
            ushort nextOffset = ReadU16(h, ramBase + ((curr + 4) & 0xffff));
            if (nextOffset == 0 || nextOffset == headOffset) break;
            curr = 0x100000 + nextOffset;
            count++;
        }
        return -1;
    }

    static bool PollNeoGeoGame(IntPtr h, bool force)
    {
        if (ramBase == 0)
        {
            long pNeo = dynamicNeoBankTable != 0 ? dynamicNeoBankTable : ResolveAddr(NEO_BANK_TABLE);
            ramBase = ReadU32(h, pNeo + 0x10 * 4);
            if (ramBase < 0x10000 || ramBase > 0x7fff0000)
            {
                ramBase = 0;
                return false;
            }
            Log("Neo-Geo RAM Base descoberto: 0x" + ramBase.ToString("X"));
        }

        // Live cursor discovery via Neo-Geo object linked list
        int c1_obj = FindCursorObject(h, ramBase, "CURSOR-1");
        int c2_obj = FindCursorObject(h, ramBase, "CURSOR-2");

        ushort phase = ReadU16(h, ramBase + 0x80c4);
        bool isCharSelect = (c1_obj != -1 || c2_obj != -1 || phase == 8 || phase == 0x0800);
        bool isStageSelect = (phase == 2 || phase == 0x0200 || phase == 3 || phase == 0x0300);

        if (!isCharSelect && !isStageSelect)
        {
            announcedCharSelect = false;
            lastP1Char = -1;
            lastP2Char = -1;
            lastP1Style = -1;
            lastP2Style = -1;
            lastP1Lock = -1;
            return false;
        }

        bool spoke = false;

        string p1Word = (currentLang == "en") ? "Player 1" : (currentLang == "es") ? "Jugador 1" : (currentLang == "ja") ? "プレイヤー1" : "Jogador 1";
        string p2Word = (currentLang == "en") ? "Player 2" : (currentLang == "es") ? "Jugador 2" : (currentLang == "ja") ? "プレイヤー2" : "Jogador 2";
        string charSelectTitle = (currentLang == "en") ? "Character Selection" : (currentLang == "es") ? "Selección de Personajes" : (currentLang == "ja") ? "キャラクター選択" : "Seleção de Personagens";
        string charWord = (currentLang == "en") ? "Character" : (currentLang == "es") ? "Personaje" : (currentLang == "ja") ? "キャラクター" : "Personagem";
        string styleWord = (currentLang == "en") ? "Style" : (currentLang == "es") ? "Estilo" : (currentLang == "ja") ? "修羅・羅刹" : "Estilo";
        string selWord = (currentLang == "en") ? "Selected" : (currentLang == "es") ? "Seleccionado" : (currentLang == "ja") ? "決定" : "Selecionado";
        string stageWord = (currentLang == "en") ? "Stage: " : (currentLang == "es") ? "Escenario: " : (currentLang == "ja") ? "ステージ: " : "Cenário: ";

        // Character Select Screen
        if (isCharSelect)
        {
            int p1Char = -1;
            if (c1_obj != -1)
            {
                p1Char = ReadU8(h, ramBase + (((c1_obj + 0xc2) ^ 1) & 0xffff));
            }
            else
            {
                byte rawId = ReadU8(h, ramBase + 0x8323);
                p1Char = CharIdToSlot(rawId);
            }

            int p2Char = -1;
            if (c2_obj != -1)
            {
                p2Char = ReadU8(h, ramBase + (((c2_obj + 0xc2) ^ 1) & 0xffff));
            }
            else
            {
                byte rawId = ReadU8(h, ramBase + 0x8322);
                p2Char = CharIdToSlot(rawId);
            }

            byte p1Style = ReadU8(h, ramBase + 0x8325);
            byte p2Style = ReadU8(h, ramBase + 0x8324);
            byte p1Lock = ReadU8(h, ramBase + 0x8327);
            byte p2Lock = ReadU8(h, ramBase + 0x8326);

            // Initial announcement on entering character selection
            if (!announcedCharSelect || force)
            {
                announcedCharSelect = true;
                string p1Name = (p1Char >= 0 && p1Char < CharacterNames.Length) ? CharacterNames[p1Char] : charWord;
                string sName = (p1Style == 1) ? "Bust" : "Slash";
                Speak(charSelectTitle + ". " + p1Word + ": " + p1Name + ", " + styleWord + " " + sName);
                lastP1Char = p1Char;
                lastP1Style = p1Style;
                lastP2Char = p2Char;
                lastP2Style = p2Style;
                lastP1Lock = p1Lock;
                return true;
            }

            // Player 1 cursor navigation across grid
            if (p1Char >= 0 && p1Char < CharacterNames.Length && p1Char != lastP1Char)
            {
                lastP1Char = p1Char;
                Speak(CharacterNames[p1Char]);
                spoke = true;
            }

            // Player 1 style switch
            if (p1Style != lastP1Style && lastP1Style != -1)
            {
                lastP1Style = p1Style;
                Speak(styleWord + ": " + ((p1Style == 1) ? "Bust" : "Slash"));
                spoke = true;
            }

            // Player 1 lock-in / confirmation
            if (p1Lock != 0 && lastP1Lock == 0 && p1Char >= 0 && p1Char < CharacterNames.Length)
            {
                lastP1Lock = p1Lock;
                string sName = (p1Style == 1) ? "Bust" : "Slash";
                Speak(CharacterNames[p1Char] + " (" + styleWord + " " + sName + ") " + selWord);
                spoke = true;
            }
            else if (p1Lock != lastP1Lock)
            {
                lastP1Lock = p1Lock;
            }

            // Player 2: ONLY if CURSOR-2 exists
            if (c2_obj != -1 && p2Char >= 0 && p2Char < CharacterNames.Length && p2Char != lastP2Char)
            {
                lastP2Char = p2Char;
                Speak(p2Word + ": " + CharacterNames[p2Char]);
                spoke = true;
            }

            if (c2_obj != -1 && p2Style != lastP2Style && lastP2Style != -1)
            {
                lastP2Style = p2Style;
                Speak(p2Word + " " + styleWord + ": " + ((p2Style == 1) ? "Bust" : "Slash"));
                spoke = true;
            }
        }

        // Pre-battle / Stage Select
        if (isStageSelect)
        {
            byte stage = ReadU8(h, ramBase + 0x836d);
            if (stage != lastStage && stage <= 9)
            {
                lastStage = stage;
                string stName = GetStageName(stage);
                Speak(stageWord + stName);
                spoke = true;
            }

            uint bg = ReadU32(h, ramBase + 0x8b4c);
            if (bg != lastBg)
            {
                lastBg = bg;
                string bgName = GetBackgroundName(bg);
                if (bgName != null)
                {
                    Speak(stageWord + bgName);
                    spoke = true;
                }
            }
        }

        return spoke;
    }

    // ---- polling ----
    // ---- polling ----
    static bool Poll(bool force)
    {
        if (hProc == IntPtr.Zero) return false;

        // 0. Dynamic language detection from SSVS.exe (DAT_005e85d0)
        long pLang = ResolveAddr(0x005e85d0);
        uint langPtr = ReadU32(hProc, pLang);
        if (langPtr >= 0x10000 && langPtr <= 0x7fff0000)
        {
            string detectedLang = ReadCString(hProc, langPtr, 8).ToLowerInvariant().Trim();
            if ((detectedLang == "pt" || detectedLang == "en" || detectedLang == "es" || detectedLang == "ja") && detectedLang != currentLang)
            {
                SetLanguage(detectedLang);
                lastDedup = null; // force immediate re-announcement of active menu
                string langName = (detectedLang == "en") ? "Language: English" :
                                  (detectedLang == "es") ? "Idioma: Español" :
                                  (detectedLang == "ja") ? "言語: 日本語" : "Idioma: Português";
                Speak(langName);
            }
        }

        // 1. First priority: front-end UI menus (MainMenu, PauseMenu, Options, SkillList, Settings, etc.)
        mgr = GetManager(hProc);
        if (mgr != 0)
        {
            uint menu = ReadU32(hProc, mgr + OFF_MGR_MENU);
            if (menu >= 0x10000 && menu <= 0x7fff0000)
            {
                uint vt = ReadU32(hProc, menu);
                uint origVt = (uint)(vt - baseDelta);
                // When in any front-end UI menu (MainMenu, Options, Pause, etc.):
                if (origVt != 0x4b8424)
                {
                    // Reset character select tracking whenever the user is in a front-end menu
                    announcedCharSelect = false;
                    lastP1Char = -1;
                    lastP2Char = -1;
                    lastP1Style = -1;
                    lastP2Style = -1;
                    lastP1Lock = -1;

                    // STRICT: Return front-end menu poll. NEVER fall through to Neo-Geo RAM while in a menu!
                    return PollMenu(hProc, menu, origVt, force);
                }
            }
        }
        // 2. Second priority: when vt == 0x4b8424 (PlayMenu), the game is actively running the arcade emulation
        return PollNeoGeoGame(hProc, force);
    }

    static int GetEngineOptionValue(IntPtr h, byte rowType)
    {
        if (rowType == 0 || rowType == (byte)' ') return -1;
        uint optBuf = ReadU32(h, ResolveAddr(0x0053e9e0));
        if (optBuf < 0x10000 || optBuf > 0x7fff0000)
            optBuf = ReadU32(h, ResolveAddr(0x005e00a0));
        if (optBuf < 0x10000 || optBuf > 0x7fff0000)
            optBuf = ReadU32(h, ResolveAddr(0x0051d030));
        if (optBuf < 0x10000 || optBuf > 0x7fff0000)
            optBuf = (uint)ResolveAddr(0x004b4668);

        byte[] str = ReadBytes(h, optBuf, 128);
        if (str != null)
        {
            for (int i = 0; i + 1 < str.Length && str[i] != 0; i += 2)
            {
                if (str[i] == rowType)
                {
                    byte valChar = str[i + 1];
                    if (valChar >= (byte)'0' && valChar <= (byte)'9')
                        return valChar - (byte)'0';
                    if (valChar == (byte)':')
                        return 10;
                    if (valChar >= (byte)'A' && valChar <= (byte)'Z')
                        return valChar - (byte)'A' + 10;
                    return valChar - (byte)'0';
                }
            }
        }
        return -1;
    }

    static bool PollMenu(IntPtr hProc, uint menu, uint vt, bool force)
    {
        string name = MenuName(vt);

        string ofWord = (currentLang == "en") ? " of " : (currentLang == "es") ? " de " : (currentLang == "ja") ? " / " : " de ";
        string p1Word = (currentLang == "en") ? "Player 1" : (currentLang == "es") ? "Jugador 1" : (currentLang == "ja") ? "プレイヤー1" : "Jogador 1";
        string p2Word = (currentLang == "en") ? "Player 2" : (currentLang == "es") ? "Jugador 2" : (currentLang == "ja") ? "プレイヤー2" : "Jogador 2";
        string optWord = (currentLang == "en") ? "Option " : (currentLang == "es") ? "Opción " : (currentLang == "ja") ? "設定 " : "Opção ";
        string moveWord = (currentLang == "en") ? "Move " : (currentLang == "es") ? "Movimiento " : (currentLang == "ja") ? "技 " : "Golpe ";
        string charWord = (currentLang == "en") ? "Character " : (currentLang == "es") ? "Personaje " : (currentLang == "ja") ? "キャラクター " : "Personagem ";
        string illustWord = (currentLang == "en") ? "Illustration " : (currentLang == "es") ? "Ilustración " : (currentLang == "ja") ? "イラスト " : "Ilustração ";
        string trophyWord = (currentLang == "en") ? "Trophy " : (currentLang == "es") ? "Trofeo " : (currentLang == "ja") ? "トロフィー " : "Troféu ";
        string boardWord = (currentLang == "en") ? "Leaderboard " : (currentLang == "es") ? "Marcador " : (currentLang == "ja") ? "ランキング " : "Placar ";

        // 1. GalleryMenu (0x4b73a4): 29 illustrations indexed in 0x5f02cc
        if (vt == 0x4b73a4)
        {
            uint gIdx = ReadU32(hProc, 0x5f02cc);
            if (gIdx >= 29) gIdx = 0;
            int g_idx = (int)gIdx;
            int g_count = 29;
            string g_disp = illustWord + (g_idx + 1);
            string g_msg = name + ", " + g_disp + ", " + (g_idx + 1) + ofWord + g_count;

            string g_dedup = vt.ToString("x8") + "|" + g_idx;
            if (!force && g_dedup == lastDedup) return false;
            lastDedup = g_dedup;
            if (verbose) Console.WriteLine("[dbg] gallery idx=" + g_idx);
            Speak(g_msg);
            return true;
        }

        // 2. TrophiesMenu (0x4b8e24): 18 trophies indexed at menu + 0x1e8 with dynamic requirements
        if (vt == 0x4b8e24)
        {
            uint tIdx = ReadU32(hProc, menu + 0x1e8);
            if (tIdx >= 18) tIdx = 0;
            int t_idx = (int)tIdx;
            int t_count = 18;

            string titleKey = "Trophy" + (t_idx + 1) + "Title";
            string bodyKey = "Trophy" + (t_idx + 1) + "Body";
            string t_title = (stringMap.ContainsKey(titleKey) && stringMap[titleKey].Length > 0) ? stringMap[titleKey] : (t_idx < TrophyNames.Length ? TrophyNames[t_idx] : (trophyWord + (t_idx + 1)));
            string t_desc = (stringMap.ContainsKey(bodyKey) && stringMap[bodyKey].Length > 0) ? stringMap[bodyKey] : "";

            string t_msg = name + ", " + t_title;
            if (t_desc.Length > 0) t_msg += ": " + t_desc;
            t_msg += ", " + (t_idx + 1) + ofWord + t_count;

            string t_dedup = vt.ToString("x8") + "|" + t_idx;
            if (!force && t_dedup == lastDedup) return false;
            lastDedup = t_dedup;
            if (verbose) Console.WriteLine("[dbg] trophies idx=" + t_idx + " title=" + t_title + " desc=" + t_desc);
            Speak(t_msg);
            return true;
        }

        // 3. LeaderboardsMenu (0x4b79cc) - mode selector
        if (vt == 0x4b79cc)
        {
            uint lIdx = ReadU32(hProc, menu + 0x160);
            uint lCnt = ReadU32(hProc, menu + 0x16c);
            if (lCnt < 1 || lCnt > 64) lCnt = (uint)LeaderboardModes.Length;
            if (lIdx >= lCnt) lIdx = 0;
            int l_idx = (int)lIdx;
            int l_count = (int)lCnt;
            string l_disp = GetLeaderboardModeName(l_idx);
            if (l_disp == null) l_disp = boardWord + (l_idx + 1);

            string l_msg = name + ", " + l_disp + ", " + (l_idx + 1) + ofWord + l_count;

            string l_dedup = vt.ToString("x8") + "|" + l_idx;
            if (!force && l_dedup == lastDedup) return false;
            lastDedup = l_dedup;
            if (verbose) Console.WriteLine("[dbg] leaderboards idx=" + l_idx);
            Speak(l_msg);
            return true;
        }

        // 3b. RankingsMenu (0x4b8684) - inside the ranking leaderboard table
        if (vt == 0x4b8684)
        {
            string r_rankWord = (currentLang == "en") ? "Rank " : (currentLang == "es") ? "Puesto " : (currentLang == "ja") ? "順位 " : "Posição ";
            string r_scoreWord = (currentLang == "en") ? "Score: " : (currentLang == "es") ? "Puntos: " : (currentLang == "ja") ? "スコア: " : "Pontos: ";

            uint selNamePtr = ReadU32(hProc, menu + OFF_MENU_SELNAME);
            string selNode = (selNamePtr >= 0x10000) ? ReadCString(hProc, selNamePtr, 32) : "";

            int lineIdx = -1;
            if (selNode.StartsWith("line"))
            {
                int ln;
                if (int.TryParse(selNode.Substring(4), out ln)) lineIdx = ln - 1;
            }

            int scroll = (int)ReadU32(hProc, menu + 0x104);
            int targetIdx = (lineIdx >= 0) ? (scroll + lineIdx) : scroll;
            int selRank = (int)ReadU32(hProc, menu + 0x140);

            uint head = ReadU32(hProc, menu + 0x74);
            uint targetEntry = 0;
            if (head >= 0x10000 && head <= 0x7fff0000)
            {
                uint curr = ReadU32(hProc, head);
                int entryIndex = 0;
                while (curr >= 0x10000 && curr <= 0x7fff0000 && curr != head && entryIndex < 100)
                {
                    uint r = ReadU32(hProc, curr + 0x94);
                    if (selRank > 0 && r == (uint)selRank)
                    {
                        targetEntry = curr;
                        break;
                    }
                    if (entryIndex == targetIdx)
                    {
                        targetEntry = curr;
                    }
                    curr = ReadU32(hProc, curr);
                    entryIndex++;
                }
            }

            if (targetEntry == 0) targetEntry = ReadU32(hProc, menu + 0xec);

            if (targetEntry >= 0x10000 && targetEntry <= 0x7fff0000)
            {
                uint rank = ReadU32(hProc, targetEntry + 0x94);
                uint score = ReadU32(hProc, targetEntry + 0x98);
                string playerName = ReadCString(hProc, targetEntry + 0x0c, 64);
                if (playerName.Length == 0) playerName = ReadCString(hProc, ReadU32(hProc, targetEntry + 8), 64);

                string r_msg = name + ", " + r_rankWord + rank + ": " + playerName + ", " + r_scoreWord + score;
                string r_dedup = vt.ToString("x8") + "|" + rank + "|" + playerName + "|" + score + "|" + selNode;
                if (!force && r_dedup == lastDedup) return false;
                lastDedup = r_dedup;
                if (verbose) Console.WriteLine("[dbg] rankings entry=" + rank + " player=" + playerName + " score=" + score);
                Speak(r_msg);
                return true;
            }
            else
            {
                int rIdx = (lineIdx >= 0) ? lineIdx : 0;
                uint rCount = ReadU32(hProc, menu + 0x74);
                if (rCount < 1 || rCount > 100) rCount = 10;
                string r_msg = name + ", " + r_rankWord + (rIdx + 1) + ofWord + rCount;
                string r_dedup = vt.ToString("x8") + "|" + rIdx + "|" + selNode;
                if (!force && r_dedup == lastDedup) return false;
                lastDedup = r_dedup;
                Speak(r_msg);
                return true;
            }
        }

        // 3c. LobbyMenu (0x4b7c54) and RoomMenu (0x4b8a8c)
        if (vt == 0x4b7c54 || vt == 0x4b8a8c)
        {
            uint ctrl = ReadU32(hProc, menu + 0x1c);
            int roomIdx = -1;
            int roomCount = 6;
            if (ctrl >= 0x10000 && ctrl <= 0x7fff0000)
            {
                roomIdx = (int)ReadU32(hProc, ctrl + 0x160);
                uint rc = ReadU32(hProc, ctrl + 0x164);
                if (rc >= 1 && rc <= 10) roomCount = (int)rc;
            }

            uint selNamePtr = ReadU32(hProc, menu + OFF_MENU_SELNAME);
            string selNode = (selNamePtr >= 0x10000) ? ReadCString(hProc, selNamePtr, 64) : "";

            byte isReady = ReadU8(hProc, menu + 0x8b);
            byte hostReady = ReadU8(hProc, menu + 0x8c);

            string itemLabel = "";
            string itemVal = "";

            if (roomIdx >= 0)
            {
                switch (roomIdx)
                {
                    case 0:
                        itemLabel = (currentLang == "pt") ? "Anfitrião" : (currentLang == "es") ? "Anfitrión" : (currentLang == "ja") ? "ホスト" : "Host";
                        break;
                    case 1:
                        itemLabel = (currentLang == "pt") ? "Atraso de Entrada" : (currentLang == "es") ? "Retardo de Entrada" : (currentLang == "ja") ? "入力遅延" : "Input Delay";
                        break;
                    case 2:
                        itemLabel = (currentLang == "pt") ? "Pronto?" : (currentLang == "es") ? "¿Listo?" : (currentLang == "ja") ? "準備完了?" : "Ready?";
                        itemVal = (isReady != 0) ? ((currentLang == "pt") ? "Sim" : (currentLang == "es") ? "Sí" : (currentLang == "ja") ? "はい" : "Yes") :
                                                   ((currentLang == "pt") ? "Não" : (currentLang == "es") ? "No" : (currentLang == "ja") ? "いいえ" : "No");
                        break;
                    case 3:
                        itemLabel = (currentLang == "pt") ? "Atraso Mínimo de Entrada" : (currentLang == "es") ? "Retardo Mínimo" : (currentLang == "ja") ? "最小入力遅延" : "Minimum Input Delay";
                        break;
                    case 4:
                        itemLabel = (currentLang == "pt") ? "Convidar" : (currentLang == "es") ? "Invitar" : (currentLang == "ja") ? "招待" : "Invite";
                        break;
                    case 5:
                        itemLabel = (currentLang == "pt") ? "Voltar" : (currentLang == "es") ? "Volver" : (currentLang == "ja") ? "戻る" : "Back";
                        break;
                    default:
                        itemLabel = optWord + (roomIdx + 1);
                        break;
                }
            }
            else
            {
                if (selNode.Contains("host")) itemLabel = (currentLang == "pt") ? "Anfitrião" : "Host";
                else if (selNode.Contains("delay_setting") || selNode.Contains("min_delay")) itemLabel = (currentLang == "pt") ? "Atraso Mínimo de Entrada" : "Minimum Input Delay";
                else if (selNode.Contains("delay")) itemLabel = (currentLang == "pt") ? "Atraso de Entrada" : "Input Delay";
                else if (selNode.Contains("ready")) {
                    itemLabel = (currentLang == "pt") ? "Pronto?" : "Ready?";
                    itemVal = (isReady != 0) ? ((currentLang == "pt") ? "Sim" : "Yes") : ((currentLang == "pt") ? "Não" : "No");
                }
                else if (selNode.Contains("invite")) itemLabel = (currentLang == "pt") ? "Convidar" : "Invite";
                else if (selNode.Contains("back")) itemLabel = (currentLang == "pt") ? "Voltar" : "Back";
                else itemLabel = selNode.Length > 0 ? selNode : name;
            }

            string r_msg = name + ", " + itemLabel;
            if (itemVal.Length > 0) r_msg += ": " + itemVal;
            if (roomIdx >= 0) r_msg += ", " + (roomIdx + 1) + ofWord + roomCount;

            string r_dedup = vt.ToString("x8") + "|" + roomIdx + "|" + isReady + "|" + hostReady + "|" + selNode;
            if (!force && r_dedup == lastDedup) return false;
            lastDedup = r_dedup;
            if (verbose) Console.WriteLine("[dbg] room vt=" + vt.ToString("x") + " idx=" + roomIdx + " node=" + selNode);
            Speak(r_msg);
            return true;
        }

        // 4. SettingsMenu family (GameSettings, DisplaySettings, VolumeSettings, SystemSettings, HostSettings, Settings)
        if (vt == 0x4b8c64 || vt == 0x4b7614 || vt == 0x4b729c || vt == 0x4b919c || vt == 0x4b8d8c || vt == 0x4b786c)
        {
            int s_idx = (int)ReadU32(hProc, menu + 0x7c);
            int s_count = (int)ReadU32(hProc, menu + 0x80);
            if (s_count <= 0 || s_count > 64) s_count = (int)ReadU32(hProc, menu + 0x9c);
            if (s_count <= 0 || s_count > 64) s_count = 8;
            if (s_idx < 0) s_idx = 0;
            if (s_idx >= s_count) s_idx = s_count - 1;

            uint keysArr = ReadU32(hProc, menu + 0x70);
            uint itemsArr = ReadU32(hProc, menu + 0x6c);

            string s_key = "";
            if (keysArr >= 0x10000)
            {
                uint kp = ReadU32(hProc, (long)keysArr + (long)s_idx * 4);
                if (kp >= 0x10000) s_key = ReadCString(hProc, kp, 64);
            }
            string keyLabel = (s_key.Length > 0 && stringMap.ContainsKey(s_key)) ? stringMap[s_key] : s_key;
            if (keyLabel.Length == 0) keyLabel = optWord + (s_idx + 1);

            int curVal = 0;
            string valDisp = "";
            if (itemsArr >= 0x10000)
            {
                long itemPtr = (long)itemsArr + (long)s_idx * 20;
                uint choiceKeys = ReadU32(hProc, itemPtr + 0);
                int numChoices = (int)ReadU32(hProc, itemPtr + 4);
                byte rowType = ReadU8(hProc, itemPtr + 8);
                // Retrieve real live option value from the engine's option buffer
                int engVal = GetEngineOptionValue(hProc, rowType);
                if (engVal >= 0)
                {
                    curVal = engVal;
                }
                else
                {
                    curVal = (int)ReadU32(hProc, itemPtr + 12);
                }
                uint choiceDisplays = ReadU32(hProc, itemPtr + 16);

                // LIVE VALUE OVERRIDE:
                // When Left/Right is pressed, SSVS writes the active modified row index to menu + 0x84
                // and the newly selected value to menu + 0x8c!
                uint lastModRow = ReadU32(hProc, menu + 0x84);
                if (lastModRow == (uint)s_idx)
                {
                    curVal = (int)ReadU32(hProc, menu + 0x8c);
                }

                if (numChoices == 11 || s_key.Contains("volume") || s_key.Contains("sfx") || s_key.Contains("music") || s_key.Contains("scanlines"))
                {
                    valDisp = (curVal * 10) + "%";
                }
                else if (rowType == (byte)'N')
                {
                    valDisp = curVal.ToString();
                }
                else if (choiceKeys >= 0x10000 && numChoices > 0 && curVal >= 0 && curVal < numChoices)
                {
                    uint ck = ReadU32(hProc, (long)choiceKeys + (long)curVal * 4);
                    if (ck >= 0x10000)
                    {
                        string cks = ReadCString(hProc, ck, 64);
                        if (cks.StartsWith("option_volume_"))
                        {
                            int v;
                            if (int.TryParse(cks.Substring(14), out v)) valDisp = (v * 10) + "%";
                            else valDisp = (curVal * 10) + "%";
                        }
                        else if (cks == "option_language_0") valDisp = "English";
                        else if (cks == "option_language_1") valDisp = "Español";
                        else if (cks == "option_language_2") valDisp = "Português";
                        else if (cks == "option_language_3") valDisp = "日本語";
                        else if (cks == "option_netcode_best") valDisp = (currentLang == "pt" ? "Melhor" : currentLang == "es" ? "Mejor" : currentLang == "ja" ? "最適" : "Best");
                        else if (cks == "option_netcode_fixed") valDisp = (currentLang == "pt" ? "Fixo" : currentLang == "es" ? "Fijo" : currentLang == "ja" ? "固定" : "Fixed");
                        else if (cks == "option_yes" || cks == "option_on") valDisp = (currentLang == "pt" ? "Ligado" : currentLang == "es" ? "Activado" : currentLang == "ja" ? "オン" : "On");
                        else if (cks == "option_no" || cks == "option_off") valDisp = (currentLang == "pt" ? "Desligado" : currentLang == "es" ? "Desactivado" : currentLang == "ja" ? "オフ" : "Off");
                        else if (stringMap.ContainsKey(cks)) valDisp = stringMap[cks];
                        else valDisp = cks;
                    }
                }
                else if (choiceDisplays >= 0x10000 && numChoices > 0 && curVal >= 0 && curVal < numChoices)
                {
                    uint dp = ReadU32(hProc, (long)choiceDisplays + (long)curVal * 4);
                    if (dp >= 0x10000) valDisp = ReadCString(hProc, dp, 64);
                }

                if (valDisp.Length == 0 && (s_key.Contains("smoothing") || s_key.Contains("suavizacao") || s_key.Contains("fullscreen") || s_key.Contains("tela_inteira")))
                {
                    valDisp = (curVal != 0) ? ((currentLang == "pt") ? "Ligado" : "On") : ((currentLang == "pt") ? "Desligado" : "Off");
                }
                else if (valDisp.Length == 0 && s_key == "option_defaults")
                {
                    // Action button, no value needed
                }
                else if (valDisp.Length == 0 && numChoices > 0)
                {
                    valDisp = curVal.ToString();
                }
            }

            string s_msg;
            if (valDisp.Length > 0)
                s_msg = name + ", " + keyLabel + ": " + valDisp + ", " + (s_idx + 1) + ofWord + s_count;
            else
                s_msg = name + ", " + keyLabel + ", " + (s_idx + 1) + ofWord + s_count;

            string s_dedup = vt.ToString("x8") + "|" + s_idx + "|" + curVal + "|" + valDisp + "|" + s_key;
            if (!force && s_dedup == lastDedup) return false;
            lastDedup = s_dedup;
            if (verbose) Console.WriteLine("[dbg] settings vt=" + vt.ToString("x") + " idx=" + s_idx + " key=" + s_key + " val=" + valDisp);
            Speak(s_msg);
            return true;
        }

        // 5. ControlSettingsMenu (0x4b6dc4)
        if (vt == 0x4b6dc4)
        {
            byte leftActive = ReadU8(hProc, menu + 0xd4);
            byte rightActive = ReadU8(hProc, menu + 0xd5);
            uint selNodePtr = ReadU32(hProc, menu + OFF_MENU_SELNAME);
            string selNode = ReadCString(hProc, selNodePtr, 32);

            string side = p1Word;
            if (rightActive != 0 || selNode.StartsWith("right"))
                side = p2Word;
            else if (leftActive != 0 || selNode.StartsWith("left"))
                side = p1Word;

            int row = (side == p2Word) ? (int)ReadU32(hProc, menu + 0x90) : (int)ReadU32(hProc, menu + 0x8c);
            if (row < 0 || row >= ControlActionKeys.Length)
            {
                if (selNode.Length >= 5)
                {
                    int n;
                    string numStr = selNode.Substring(selNode.LastIndexOf('_') + 1);
                    if (numStr.StartsWith("line") && int.TryParse(numStr.Substring(4), out n)) row = n - 1;
                    else if (int.TryParse(numStr, out n)) row = n - 1;
                }
            }
            if (row < 0 || row >= ControlActionKeys.Length) row = 0;

            string action = GetControlActionName(row);
            int totalRows = ControlActionKeys.Length;
            string c_msg = name + ", " + side + ", " + action + ", " + (row + 1) + ofWord + totalRows;

            string c_dedup = vt.ToString("x8") + "|" + side + "|" + row;
            if (!force && c_dedup == lastDedup) return false;
            lastDedup = c_dedup;
            if (verbose) Console.WriteLine("[dbg] controls side=" + side + " row=" + row);
            Speak(c_msg);
            return true;
        }

        // 6. CommandListMenu (0x4b6ac4)
        if (vt == 0x4b6ac4)
        {
            int cl_count = (int)ReadU32(hProc, menu + 0x6c);
            int cl_idx = (int)ReadU32(hProc, menu + 0x70);
            if (cl_count <= 0 || cl_count > 128) cl_count = 1;
            if (cl_idx < 0) cl_idx = 0;
            if (cl_idx >= cl_count) cl_idx = cl_count - 1;

            string cl_title = ReadCString(hProc, ReadU32(hProc, menu + 0x94 + (long)cl_idx * 4), 64);
            string cl_cmd = ReadCString(hProc, ReadU32(hProc, menu + 0xe4 + (long)cl_idx * 4), 128);

            if (cl_title.Length > 0 && stringMap.ContainsKey(cl_title))
                cl_title = stringMap[cl_title];
            if (cl_title.Length == 0) cl_title = moveWord + (cl_idx + 1);

            string formattedCmd = FormatCommandText(cl_cmd);

            string cl_msg;
            if (formattedCmd.Length > 0)
                cl_msg = name + ", " + cl_title + ": " + formattedCmd + ", " + (cl_idx + 1) + ofWord + cl_count;
            else
                cl_msg = name + ", " + cl_title + ", " + (cl_idx + 1) + ofWord + cl_count;

            string cl_dedup = vt.ToString("x8") + "|" + cl_idx + "|" + cl_title + "|" + cl_cmd;
            if (!force && cl_dedup == lastDedup) return false;
            lastDedup = cl_dedup;
            if (verbose) Console.WriteLine("[dbg] commandlist idx=" + cl_idx + " title=" + cl_title + " cmd=" + formattedCmd);
            Speak(cl_msg);
            return true;
        }

        // 7. HiddenCharactersMenu (0x4b76b4)
        if (vt == 0x4b76b4)
        {
            int hc_count = (int)ReadU32(hProc, menu + 0x70);
            int hc_idx = (int)ReadU32(hProc, menu + 0x74);
            if (hc_count <= 0 || hc_count > 16) hc_count = 5;
            if (hc_idx < 0) hc_idx = 0;
            if (hc_idx >= hc_count) hc_idx = hc_count - 1;

            string hc_name = ReadCString(hProc, ReadU32(hProc, menu + 0x7c + (long)hc_idx * 4), 64);
            string hc_code = ReadCString(hProc, ReadU32(hProc, menu + 0xcc + (long)hc_idx * 4), 128);

            if (hc_name.Length > 0 && stringMap.ContainsKey(hc_name))
                hc_name = stringMap[hc_name];
            if (hc_name.Length == 0) hc_name = charWord + (hc_idx + 1);

            string formattedCode = FormatCommandText(hc_code);

            string hc_msg;
            if (formattedCode.Length > 0)
                hc_msg = name + ", " + hc_name + ": " + formattedCode + ", " + (hc_idx + 1) + ofWord + hc_count;
            else
                hc_msg = name + ", " + hc_name + ", " + (hc_idx + 1) + ofWord + hc_count;

            string hc_dedup = vt.ToString("x8") + "|" + hc_idx + "|" + hc_name + "|" + hc_code;
            if (!force && hc_dedup == lastDedup) return false;
            lastDedup = hc_dedup;
            if (verbose) Console.WriteLine("[dbg] hiddenchars idx=" + hc_idx + " name=" + hc_name);
            Speak(hc_msg);
            return true;
        }

        // 8. Standard menus (MainMenu, MultiplayerMenu, InGameOptionsMenu, PauseMenu, etc.)
        uint arr = ReadU32(hProc, menu + OFF_MENU_LABELARR);
        uint count = ReadU32(hProc, menu + 0x74);
        if (count < 1 || count > 64) count = ReadU32(hProc, menu + OFF_MENU_COUNT);

        int idx = ReadSelectedIndex(hProc, menu);

        if ((count < 1 || count > 256) && arr >= RDATA_LO && arr <= 0x7fff0000)
        {
            int derived = DeriveCount(hProc, arr);
            if (derived >= 1) count = (uint)derived;
        }

        string key = "";
        if (idx >= 0 && arr >= 0x10000)
        {
            uint kp = ReadU32(hProc, (long)arr + (long)idx * 4);
            if (kp >= 0x10000) key = ReadCString(hProc, kp, 128);
        }
        string nodeName = ReadCString(hProc, ReadU32(hProc, menu + OFF_MENU_SELNAME), 64);
        if (!IsPrintableKey(key)) key = IsPrintableKey(nodeName) ? nodeName : "";

        // Disambiguation for MultiplayerMenu (0x4b807c)
        string disp;
        if (vt == 0x4b807c)
        {
            count = 4;
            if (currentLang == "en")
            {
                switch (idx)
                {
                    case 0: disp = "Quick Match"; break;
                    case 1: disp = "Create Match (Versus)"; break;
                    case 2: disp = "Create Match (Training)"; break;
                    case 3: disp = "Create Match (Story)"; break;
                    default: disp = (key.Length > 0 && stringMap.ContainsKey(key)) ? stringMap[key] : key; break;
                }
            }
            else if (currentLang == "es")
            {
                switch (idx)
                {
                    case 0: disp = "Buscar Partida"; break;
                    case 1: disp = "Crear Partida (Versus)"; break;
                    case 2: disp = "Crear Partida (Entrenamiento)"; break;
                    case 3: disp = "Crear Partida (Historia)"; break;
                    default: disp = (key.Length > 0 && stringMap.ContainsKey(key)) ? stringMap[key] : key; break;
                }
            }
            else if (currentLang == "ja")
            {
                switch (idx)
                {
                    case 0: disp = "クイックマッチ"; break;
                    case 1: disp = "マッチ作成 (VS)"; break;
                    case 2: disp = "マッチ作成 (トレーニング)"; break;
                    case 3: disp = "マッチ作成 (ストーリー)"; break;
                    default: disp = (key.Length > 0 && stringMap.ContainsKey(key)) ? stringMap[key] : key; break;
                }
            }
            else // pt
            {
                switch (idx)
                {
                    case 0: disp = "Procurar Partida"; break;
                    case 1: disp = "Criar Partida (Versus)"; break;
                    case 2: disp = "Criar Partida (Treino)"; break;
                    case 3: disp = "Criar Partida (História)"; break;
                    default: disp = (key.Length > 0 && stringMap.ContainsKey(key)) ? stringMap[key] : key; break;
                }
            }
        }
        else
        {
            if (key.Length > 0 && stringMap.ContainsKey(key)) disp = stringMap[key];
            else disp = key;
        }

        bool haveCount = (count >= 1 && count <= 256 && idx >= 0 && idx < (int)count);
        string msg;
        if (haveCount)
            msg = name + ", " + disp + ", " + (idx + 1) + ofWord + count;
        else if (idx >= 0 && disp.Length > 0)
            msg = name + ", " + disp;
        else
            msg = name;

        string dedup = vt.ToString("x8") + "|" + idx + "|" + key;
        if (!force && dedup == lastDedup) return false;
        lastDedup = dedup;

        if (verbose)
        {
            Console.WriteLine("[dbg] mgr=0x" + mgr.ToString("x") + " menu=0x" + menu.ToString("x") +
                              " vt=0x" + vt.ToString("x") + " arr=0x" + arr.ToString("x") +
                              " count=" + count + " idx=" + idx + " key='" + key + "'");
        }

        Speak(msg);
        return true;
    }

    static void SpeakMenuName()
    {
        if (hProc == IntPtr.Zero) return;
        if (mgr == 0) mgr = ScanForManager(hProc);
        if (mgr == 0) return;
        uint menu = ReadU32(hProc, mgr + OFF_MGR_MENU);
        if (menu < 0x10000) return;
        uint vt = ReadU32(hProc, menu);
        Speak(MenuName(vt));
    }

    // ---- hotkey edge detection ----
    static bool Edge(int vk)
    {
        if (vk < 0 || vk > 255) return false;
        short st = GetAsyncKeyState(vk);
        bool down = (st & 0x8000) != 0;
        bool pressed = down && !keyWasDown[vk];
        keyWasDown[vk] = down;
        return pressed;
    }

    // ---- announcer chain: NVDA ONLY (Prism NVDA backend or direct nvdaControllerClient) ----
    static bool InitPrism()
    {
        try
        {
            if (prismCtx == IntPtr.Zero)
            {
                prismCtx = prism_init(IntPtr.Zero);
                if (prismCtx == IntPtr.Zero) return false;
            }
            if (prismBackend == IntPtr.Zero)
            {
                prismBackend = prism_registry_acquire_best(prismCtx);
                if (prismBackend != IntPtr.Zero)
                {
                    IntPtr np = prism_backend_name(prismBackend);
                    prismBackendName = Marshal.PtrToStringAnsi(np);
                    Log("Prism acquired backend: " + prismBackendName);
                    // REQUIRE NVDA: if Prism did not acquire NVDA (e.g. OneCore or SAPI), reject it immediately
                    if (!string.Equals(prismBackendName, "NVDA", StringComparison.OrdinalIgnoreCase))
                    {
                        Log("Rejecting non-NVDA Prism backend: " + prismBackendName + " (NVDA ONLY enforced)");
                        prismBackend = IntPtr.Zero;
                        return false;
                    }
                    prism_backend_initialize(prismBackend);
                }
            }
            return prismBackend != IntPtr.Zero;
        }
        catch (Exception ex)
        {
            Log("InitPrism error: " + ex.Message);
            return false;
        }
    }

    static bool TryPrism(string text)
    {
        try
        {
            if (!InitPrism()) return false;
            byte[] utf8 = Encoding.UTF8.GetBytes(text + "\0");
            int r = prism_backend_speak(prismBackend, utf8, true);
            return r == 0;
        }
        catch { return false; }
    }

    static void Speak(string text)
    {
        if (text == null || text.Length == 0) return;
        Console.WriteLine("SAY: " + text);
        Log("SPEAK: " + text);
        if (mute) return;

        // User requested ONLY NVDA: prioritize direct nvdaControllerClient (pure UTF-16 Unicode),
        // with Prism (NVDA backend, UTF-8) as secondary.
        // Never fall back to SAPI or OneCore unless explicitly passed -Speaker sapi
        if (speakerMode == "nvda" || speakerMode == "auto" || speakerMode == "prism")
        {
            if (TryNvda(text)) { Log("[fala -> nvdaControllerClient]"); return; }
            if (TryPrism(text)) { Log("[fala -> prism (NVDA)]"); return; }
            
            if (speakerMode == "auto")
            {
                Log("[NVDA indisponivel -> tentando fallback SAPI/UIA]");
                if (TrySapi(text)) { Log("[fala -> SAPI fallback]"); return; }
                if (TryUia(text)) { Log("[fala -> UIA fallback]"); return; }
            }
            Log("[Aviso: nenhum sintetizador de voz respondeu para falar]");
            return;
        }

        if (speakerMode == "sapi")
        {
            if (TrySapi(text)) { Log("[fala -> sapi]"); return; }
            return;
        }
        if (speakerMode == "uia")
        {
            if (TryUia(text)) { Log("[fala -> uia]"); return; }
            return;
        }
    }

    static bool TryNvda(string text)
    {
        try
        {
            int test = nvdaController_testIfRunning();
            if (test != 0) return false;
            nvdaController_cancelSpeech();
            int r = nvdaController_speakText(text);
            return r == 0;
        }
        catch (Exception ex)
        {
            Log("TryNvda falhou: " + ex.Message);
            return false;
        }
    }

    static bool TryUia(string text)
    {
        try
        {
            if (uiaProvider == IntPtr.Zero)
            {
                uiaForm = new Form();
                uiaForm.ShowInTaskbar = false;
                uiaForm.FormBorderStyle = FormBorderStyle.None;
                uiaForm.StartPosition = FormStartPosition.Manual;
                uiaForm.Location = new System.Drawing.Point(-32000, -32000);
                uiaForm.Size = new System.Drawing.Size(1, 1);
                IntPtr hwnd = uiaForm.Handle;
                IntPtr prov;
                int hr = UiaHostProviderFromHwnd(hwnd, out prov);
                if (hr != 0 || prov == IntPtr.Zero) return false;
                uiaProvider = prov;
            }
            // NotificationKind=4 (Other), NotificationProcessing=1 (ImportantMostRecent)
            int hr2 = UiaRaiseNotificationEvent(uiaProvider, 4, 1, text, "ssvs");
            return hr2 == 0;
        }
        catch { return false; }
    }

    static bool TrySapi(string text)
    {
        try
        {
            if (sapi == null)
            {
                Type t = Type.GetTypeFromProgID("SAPI.SpVoice");
                if (t == null) return false;
                sapi = Activator.CreateInstance(t);
            }
            // flags 3 = SVSFlagsAsync(1) | SVSFPurgeBeforeSpeak(2)
            sapi.GetType().InvokeMember("Speak", BindingFlags.InvokeMethod, null, sapi, new object[] { text, 3 });
            return true;
        }
        catch { return false; }
    }
}
