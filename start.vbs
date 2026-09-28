' Double-click to open DocIt with no command windows.
'
' Starts the evidence dashboard in the background; it opens your browser,
' starts the capture listener, and starts Docker Desktop if it isn't up.
' Opened twice, it just shows the dashboard that's already running.
' Stop everything with "Shut down" in the dashboard. Nothing that would
' have been printed is lost: see the dashboard's Logs page (logs\*.log).
Option Explicit
Dim fso, shell, here, pythonw
Set fso = CreateObject("Scripting.FileSystemObject")
here = fso.GetParentFolderName(WScript.ScriptFullName)
pythonw = here & "\venv\Scripts\pythonw.exe"
If Not fso.FileExists(pythonw) Then
    MsgBox "The Python environment is missing. From this folder, run:" & vbCrLf & vbCrLf & _
           "    python -m venv venv" & vbCrLf & _
           "    venv\Scripts\pip install -r requirements.txt", vbExclamation, "DocIt"
    WScript.Quit 1
End If
Set shell = CreateObject("WScript.Shell")
shell.CurrentDirectory = here
' 0 = no window, False = don't wait for it.
shell.Run """" & pythonw & """ """ & here & "\gui\app.py"" --open", 0, False
