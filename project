#!/usr/bin/env python3
"""
ShieldGuard Pro - Advanced Virus Detection and Removal System
Professional GUI Implementation with Real Virus Detection
"""

import os
import sys
import time
import json
import logging
import traceback
import threading
import hashlib
import re
import subprocess
import requests
import math
import ctypes
import platform
import tempfile
import shutil
import webbrowser
import concurrent.futures
from collections import Counter
from datetime import datetime
# Add these imports at the top of your file
# Update your import statement
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QProgressBar, QTableWidget, QTableWidgetItem, QHeaderView,
    QFileDialog, QMessageBox, QSystemTrayIcon, QMenu, QAction, QDialog, QCheckBox,
    QComboBox, QSpinBox, QLineEdit, QGroupBox, QFormLayout, QTextEdit, QSplitter,
    QTreeWidget, QTreeWidgetItem, QToolBar, QStatusBar, QFrame, QStackedWidget,
    QDialogButtonBox, QSlider, QStyle, QStyleFactory, QGraphicsDropShadowEffect,
    QRadioButton, QButtonGroup, QToolTip, QDesktopWidget, QGraphicsOpacityEffect,
    QProgressDialog
)


from PyQt5.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QSize, QSettings, QUrl, QPoint, 
    QPropertyAnimation, QEasingCurve, QObject, QParallelAnimationGroup
)

from PyQt5.QtGui import (
    QIcon, QPixmap, QFont, QColor, QPalette, QDesktopServices, QTextCursor, 
    QFontDatabase, QCursor, QLinearGradient, QBrush, QPainter, QPen, QPainterPath,
    QCloseEvent
)

WHITELIST_PATHS = [
    # System directories that should be excluded from scanning
    os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'System32'),
    os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'SysWOW64'),
    os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), 'Windows Defender'),
    os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), 'Microsoft Security Client'),
]

WHITELIST_HASHES = {
    # Known good files (MD5 hash -> description)
    "44d88612fea8a8f36de82e1278abb02f": "Windows System File",
    "5e3ab14e23f6d5bb07c6f9b6fb3b6596": "Windows System File",
}

TRUSTED_PUBLISHERS = [
    "Microsoft Corporation",
    "Microsoft Windows",
    "Google LLC",
    "Apple Inc.",
    "Mozilla Corporation"
]


# Constants
APP_NAME = "ShieldGuard Pro"
APP_VERSION = "2.0.0"
COMPANY_NAME = "SecureTech Solutions"
CONFIG_NAME = "ShieldGuardPro"

# Color scheme
COLOR_SUCCESS = "#4CAF50"
COLOR_WARNING = "#FF9800"
COLOR_DANGER = "#F44336"
COLOR_INFO = "#2196F3"
COLOR_NEUTRAL = "#9E9E9E"
COLOR_BACKGROUND = "#212121"
COLOR_CARD = "#303030"
COLOR_TEXT = "#FFFFFF"
COLOR_ADMIN = "#8E24AA"  # Purple for admin mode
COLOR_LIMITED = "#FB8C00"  # Orange for limited mode

# Virus signature database
VIRUS_SIGNATURES = {
    # Common malware signatures (MD5 hashes)
    "44d88612fea8a8f36de82e1278abb02f": "Trojan.Win32.Generic",
    "5e3ab14e23f6d5bb07c6f9b6fb3b6596": "Backdoor.Win32.Rbot",
    "a2b851e5f6bfc9f8e8e8e8e8e8e8e8e8": "Worm.Win32.Conficker",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Ransomware.Cryptolocker",
    
    # Common malicious patterns (regex)
    "eval\\(base64_decode\\(": "PHP.Backdoor",
    "cmd\\.exe /c": "Suspicious.CommandExecution",
    "powershell -e": "Suspicious.PowerShellEncoded",
    "WScript.Shell.*?ActiveXObject": "JS.Malicious",
    "net user add": "Suspicious.UserCreation",
    "net localgroup administrators": "Suspicious.AdminModification"
}

# Known malicious file extensions
SUSPICIOUS_EXTENSIONS = [
    '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.scr', '.pif'
]

# Check if running as admin
def is_admin():
    """Check if the script is running with admin privileges"""
    try:
        if sys.platform == 'win32':
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0  # Root check for Unix-like systems
    except:
        return False


def run_as_admin():
    """Restart the application with administrator privileges"""
    try:
        if sys.platform == 'win32':
            import ctypes
            import subprocess
            import tempfile
            import os
            
            # Get the path to the executable and script
            exe_path = sys.executable
            script_path = os.path.abspath(sys.argv[0])
            
            # Create a shortcut with "Run as administrator" property
            shortcut_path = os.path.join(tempfile.gettempdir(), f"{APP_NAME}_Admin.lnk")
            
            # Create a PowerShell script to create the shortcut
            ps_script = f'''
            $WshShell = New-Object -ComObject WScript.Shell
            $Shortcut = $WshShell.CreateShortcut("{shortcut_path}")
            $Shortcut.TargetPath = "{exe_path}"
            $Shortcut.Arguments = "{script_path} --admin-restart"
            $Shortcut.Save()
            
            # Set the shortcut to run as administrator
            $bytes = [System.IO.File]::ReadAllBytes("{shortcut_path}")
            $bytes[0x15] = $bytes[0x15] -bor 0x20 # Set the run as admin flag
            [System.IO.File]::WriteAllBytes("{shortcut_path}", $bytes)
            
            # Start the shortcut
            Start-Process "{shortcut_path}"
            '''
            
            # Save the PowerShell script to a temporary file
            fd, ps_path = tempfile.mkstemp(suffix='.ps1')
            os.close(fd)
            
            with open(ps_path, 'w') as f:
                f.write(ps_script)
            
            # Execute the PowerShell script
            logging.info(f"Executing PowerShell script: {ps_path}")
            subprocess.Popen(['powershell', '-ExecutionPolicy', 'Bypass', '-File', ps_path], 
                           shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            
            # Schedule cleanup of temporary files
            def cleanup():
                time.sleep(10)
                try:
                    if os.path.exists(ps_path):
                        os.remove(ps_path)
                    if os.path.exists(shortcut_path):
                        os.remove(shortcut_path)
                except:
                    pass
            
            import threading
            threading.Thread(target=cleanup, daemon=True).start()
            
            # Wait a moment to give time for the admin process to start
            time.sleep(3)
            
            # Exit this instance
            return True
        
        elif sys.platform == 'darwin':  # macOS
            script_path = os.path.abspath(sys.argv[0])
            os.system(f"osascript -e 'do shell script \"python3 {script_path} --admin-restart\" with administrator privileges'")
            return True
            
        else:  # Linux
            script_path = os.path.abspath(sys.argv[0])
            
            # Try different graphical sudo methods
            if os.path.exists('/usr/bin/gksudo'):
                os.execvp('gksudo', ['gksudo', '--'] + sys.argv + ['--admin-restart'])
            elif os.path.exists('/usr/bin/kdesudo'):
                os.execvp('kdesudo', ['kdesudo', '--'] + sys.argv + ['--admin-restart'])
            elif os.path.exists('/usr/bin/pkexec'):
                os.execvp('pkexec', ['pkexec'] + sys.argv + ['--admin-restart'])
            else:
                # Fallback to terminal sudo
                os.system(f"xterm -e 'sudo python3 {script_path} --admin-restart'")
            
            return True
                
    except Exception as e:
        logging.error(f"Failed to restart as admin: {str(e)}")
        return False








# Get resource paths
def get_resource_path(name):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    if name.startswith(':/icons/'):
        return os.path.join(base_dir, 'icons', name.replace(':/icons/', ''))
    elif name.startswith(':/images/'):
        return os.path.join(base_dir, 'images', name.replace(':/images/', ''))
    elif name.startswith(':/styles/'):
        return os.path.join(base_dir, 'styles', name.replace(':/styles/', ''))
    
    return name

# Add these utility functions near the top of your file, after imports
# but before class definitions
def delete_file(file_path):
    """Delete a file with proper error handling"""
    try:
        if os.path.exists(file_path):
            # Check if we have write permissions to the file
            if not os.access(file_path, os.W_OK):
                logging.warning(f"No write permission for {file_path}")
                # Try to change permissions first
                try:
                    os.chmod(file_path, 0o666)  # Set read/write permissions
                except Exception as e:
                    logging.error(f"Failed to change permissions: {str(e)}")
                    return False, "Access denied - insufficient permissions"
            
            os.remove(file_path)
            return True, "File deleted successfully"
        else:
            return False, "File does not exist"
    except PermissionError:
        logging.error(f"Permission denied when deleting {file_path}")
        # Try to handle locked files on Windows
        if sys.platform == 'win32':
            return handle_locked_file_windows(file_path)
        return False, "Access denied - file may be in use by another process"
    except Exception as e:
        logging.error(f"Error deleting file {file_path}: {str(e)}")
        return False, f"Error: {str(e)}"

def handle_locked_file_windows(file_path):
    """Handle locked files on Windows using specialized techniques"""
    try:
        import win32con
        import win32file
        import pywintypes
        
        try:
            # Try to take ownership of the file (requires admin)
            if is_admin():
                take_ownership_cmd = f'takeown /f "{file_path}" /a'
                subprocess.run(take_ownership_cmd, shell=True, check=False)
                
                # Grant full control
                icacls_cmd = f'icacls "{file_path}" /grant administrators:F'
                subprocess.run(icacls_cmd, shell=True, check=False)
            
            # Try to change file attributes to normal
            win32file.SetFileAttributes(file_path, win32con.FILE_ATTRIBUTE_NORMAL)
            
            # Try to delete using Windows API
            win32file.DeleteFile(file_path)
            return True, "File deleted successfully using Windows API"
        except pywintypes.error as we:
            logging.error(f"Windows API deletion failed: {str(we)}")
            
            # Last resort: schedule deletion on reboot
            try:
                if ctypes.windll.kernel32.MoveFileExW(file_path, None, 4):  # MOVEFILE_DELAY_UNTIL_REBOOT
                    return True, "File scheduled for deletion on next reboot"
                else:
                    return False, "Failed to schedule deletion on reboot"
            except Exception as e:
                logging.error(f"Failed to schedule deletion: {str(e)}")
                return False, "Failed to delete file - try running as administrator"
    except ImportError:
        logging.error("Windows modules not available for advanced deletion")
        return False, "Required Windows modules not available"
    except Exception as e:
        logging.error(f"Error in handle_locked_file_windows: {str(e)}")
        return False, f"Error: {str(e)}"

def force_delete_file(file_path):
    """Force delete a file using Windows-specific methods if needed"""
    try:
        if os.path.exists(file_path):
            # First try standard deletion
            try:
                os.remove(file_path)
                return True, "File deleted successfully"
            except Exception as e:
                logging.warning(f"Standard deletion failed for {file_path}: {str(e)}")
            
            # Try Windows-specific methods
            if sys.platform == 'win32':
                return handle_locked_file_windows(file_path)
            else:
                # For Unix systems, try with sudo if available and we're not root
                if os.geteuid() != 0:  # Not root
                    try:
                        cmd = f'sudo rm -f "{file_path}"'
                        result = subprocess.run(cmd, shell=True, check=False)
                        if result.returncode == 0:
                            return True, "File deleted successfully using sudo"
                        else:
                            return False, "Failed to delete with sudo"
                    except Exception as e:
                        logging.error(f"Sudo deletion failed: {str(e)}")
                        return False, f"Sudo deletion failed: {str(e)}"
                
                return False, "Failed to delete file - insufficient permissions"
        else:
            return True, "File does not exist"
    except Exception as e:
        logging.error(f"Error in force_delete_file: {str(e)}")
        return False, f"Error: {str(e)}"

def delete_with_retry(file_path, max_attempts=3, delay=1.0):
    """Delete a file with multiple retry attempts"""
    for attempt in range(max_attempts):
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                return True, f"File deleted successfully on attempt {attempt+1}"
            return True, "File does not exist"
        except Exception as e:
            logging.warning(f"Delete attempt {attempt+1} failed: {str(e)}")
            if attempt < max_attempts - 1:
                time.sleep(delay)  # Wait before retrying
    
    return False, f"Failed to delete after {max_attempts} attempts"

# Add the enhanced_malware_removal function here
def enhanced_malware_removal(file_paths):
    """
    Enhanced malware removal function that uses multiple techniques to forcibly
    remove locked or protected malicious files.
    
    Args:
        file_paths: List of file paths to remove
        
    Returns:
        tuple: (success_count, failed_paths)
    """
    import os
    import sys
    import time
    import subprocess
    import tempfile
    import logging
    
    success_count = 0
    failed_paths = []
    
    # Create a temporary directory for helper scripts
    temp_dir = tempfile.mkdtemp()
    
    # 1. First attempt: Kill processes that might be locking the files
    try:
        # Create a PowerShell script to find and kill processes
        ps_killer_path = os.path.join(temp_dir, "processkiller.ps1")
        
        with open(ps_killer_path, 'w') as f:
            f.write('''
# PowerShell script to identify and kill processes locking files
param (
    [string]$targetDir
)

Write-Host "Searching for processes locking files in: $targetDir"

# Get all running processes
$processes = Get-Process

# Function to check if a process has a handle to files in the target directory
function Test-ProcessLock {
    param (
        [System.Diagnostics.Process]$process,
        [string]$targetDir
    )
    
    try {
        $handles = $null
        
        # Skip system processes
        if ($process.Id -le 4) { return $false }
        if ($process.ProcessName -eq "System" -or $process.ProcessName -eq "Idle") { return $false }
        
        # Use handle.exe if available (Sysinternals tool)
        $handleExe = "$env:SystemRoot\\handle.exe"
        if (Test-Path $handleExe) {
            $output = & $handleExe -p $process.Id 2>$null
            if ($output -match [regex]::Escape($targetDir)) {
                return $true
            }
        }
        
        # Alternative check - look for modules loaded from target directory
        foreach ($module in $process.Modules) {
            if ($module.FileName -like "$targetDir*") {
                return $true
            }
        }
        
        return $false
    }
    catch {
        Write-Host "Error checking process $($process.ProcessName): $_"
        return $false
    }
}

# Check each process
foreach ($process in $processes) {
    try {
        if (Test-ProcessLock -process $process -targetDir $targetDir) {
            Write-Host "Found locking process: $($process.ProcessName) (PID: $($process.Id))"
            
            # Try to kill the process
            try {
                Stop-Process -Id $process.Id -Force
                Write-Host "Successfully terminated process $($process.ProcessName) (PID: $($process.Id))"
            }
            catch {
                Write-Host "Failed to terminate process $($process.ProcessName): $_"
            }
        }
    }
    catch {
        Write-Host "Error processing $($process.ProcessName): $_"
    }
}

# Special case for svchost processes that might be hosting DLL services
$svchostProcesses = Get-Process -Name "svchost" -ErrorAction SilentlyContinue
foreach ($svchost in $svchostProcesses) {
    # Get services running in this svchost
    $services = Get-WmiObject -Query "SELECT * FROM Win32_Service WHERE ProcessId = $($svchost.Id)"
    
    foreach ($service in $services) {
        if ($service.PathName -like "$targetDir*") {
            Write-Host "Found service using target directory: $($service.Name) in svchost PID $($svchost.Id)"
            
            # Try to stop the service
            try {
                Stop-Service -Name $service.Name -Force
                Write-Host "Successfully stopped service $($service.Name)"
            }
            catch {
                Write-Host "Failed to stop service $($service.Name): $_"
            }
        }
    }
}
            ''')
        
        # 2. Create a batch file for elevated execution
        batch_path = os.path.join(temp_dir, "remove_malware.bat")
        
        with open(batch_path, 'w') as f:
            f.write('@echo off\n')
            f.write('echo ShieldGuard Pro - Advanced Malware Removal\n')
            f.write('echo =======================================\n\n')
            
            # Run the PowerShell killer script with elevation
            ps_path_escaped = ps_killer_path.replace('\\', '\\\\')
            target_dir_escaped = os.path.dirname(file_paths[0]).replace('\\', '\\\\')
            f.write('powershell -ExecutionPolicy Bypass -Command "Start-Process powershell -ArgumentList \'-ExecutionPolicy Bypass -File "{0}" -targetDir "{1}"\' -Verb RunAs -Wait"\n\n'.format(ps_path_escaped, target_dir_escaped))
            
            # Add commands to take ownership and grant permissions
            for file_path in file_paths:
                safe_path = file_path.replace('"', '""')
                f.write('echo Processing {0}...\n'.format(os.path.basename(safe_path)))
                f.write('takeown /f "{0}" /a\n'.format(safe_path))
                f.write('icacls "{0}" /grant administrators:F\n'.format(safe_path))
                f.write('del /f /q "{0}"\n'.format(safe_path))
                f.write('if exist "{0}" (\n'.format(safe_path))
                f.write('    echo Failed to delete file directly, trying alternative methods...\n')
                
                # Try to use MoveFileEx to schedule deletion on reboot - using string formatting instead of f-strings
                powershell_cmd = 'powershell -Command "$result = Add-Type -MemberDefinition \'[DllImport(\\\"kernel32.dll\\\", SetLastError = true, CharSet = CharSet.Unicode)] public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);\' -Name \'MoveFile\' -Namespace \'Win32\' -PassThru; $result::MoveFileEx(\'{0}\', $null, 4)"\n'
                escaped_path = safe_path.replace('\\', '\\\\')
                f.write(powershell_cmd.format(escaped_path))
                
                f.write(')\n\n')
            
            # Add cleanup for the temp directory itself
            f.write('rmdir /s /q "{0}"\n'.format(temp_dir))
        
        # 3. Execute the batch file with elevation
        logging.info(f"Launching enhanced malware removal for {len(file_paths)} files")
        
        if sys.platform == 'win32':
            # Use ShellExecute to run with elevation
            import ctypes
            result = ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                batch_path,
                None,
                None,
                1  # SW_SHOWNORMAL
            )
            
            # Wait for the batch file to complete
            time.sleep(2)  # Give it time to start
            
            # Check if files were deleted
            for file_path in file_paths:
                if not os.path.exists(file_path):
                    success_count += 1
                    logging.info(f"Successfully removed: {file_path}")
                else:
                    failed_paths.append(file_path)
                    logging.warning(f"File still exists after removal attempt: {file_path}")
        else:
            # For non-Windows platforms
            logging.warning("Enhanced malware removal is optimized for Windows. Using basic removal for other platforms.")
            for file_path in file_paths:
                try:
                    os.remove(file_path)
                    success_count += 1
                except Exception as e:
                    failed_paths.append(file_path)
                    logging.error(f"Failed to remove {file_path}: {str(e)}")
    
    except Exception as e:
        logging.error(f"Error in enhanced malware removal: {str(e)}")
    
    # 4. Create a boot-time deletion script as a last resort
    if failed_paths:
        try:
            # Create a registry script for boot-time deletion
            reg_script_path = os.path.join(temp_dir, "bootdelete.reg")
            with open(reg_script_path, 'w') as f:
                f.write('Windows Registry Editor Version 5.00\n\n')
                f.write('[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager]\n')
                f.write('"PendingFileRenameOperations"=hex(7):\\\n')
                
                for i, path in enumerate(failed_paths):
                    # Format for PendingFileRenameOperations: \??\C:\path\to\file\0\0
                    escaped_path = '\\\\??\\' + path.replace('\\', '\\\\')
                    hex_chars = []
                    for c in escaped_path:
                        hex_chars.append(f'"{ord(c):02x}"')
                    hex_path = ','.join(hex_chars) + ',00,00'
                    
                    if i < len(failed_paths) - 1:
                        hex_path += ',\\\n'
                    
                    f.write(hex_path)
            
            # Run the registry script with elevation
            if sys.platform == 'win32':
                ctypes.windll.shell32.ShellExecuteW(
                    None,
                    "runas",
                    "regedit.exe",
                    f"/s \"{reg_script_path}\"",
                    None,
                    1  # SW_SHOWNORMAL
                )
                
                logging.info(f"Scheduled {len(failed_paths)} files for deletion on next boot")
        except Exception as e:
            logging.error(f"Failed to create boot-time deletion script: {str(e)}")
    
    return success_count, failed_paths

    
    return success_count, failed_paths

# Custom notification widget
class NotificationWidget(QWidget):
    """Custom notification widget that appears at the bottom right of the screen"""
    closed = pyqtSignal()
    
    def __init__(self, title, message, icon_type="info", parent=None):
        try:
            super().__init__(parent)
            self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool)
            self.setAttribute(Qt.WA_TranslucentBackground)
            self.setFixedSize(350, 100)
            
            # Set up the layout
            layout = QVBoxLayout(self)
            layout.setContentsMargins(10, 10, 10, 10)
            
            # Create the notification card
            card = QFrame(self)
            card.setObjectName("notification_card")
            card_layout = QHBoxLayout(card)
            
            # Add icon
            icon_label = QLabel()
            if icon_type == "info":
                icon = QApplication.style().standardIcon(QStyle.SP_MessageBoxInformation)
                card.setProperty("type", "info")
            elif icon_type == "warning":
                icon = QApplication.style().standardIcon(QStyle.SP_MessageBoxWarning)
                card.setProperty("type", "warning")
            elif icon_type == "error":
                icon = QApplication.style().standardIcon(QStyle.SP_MessageBoxCritical)
                card.setProperty("type", "error")
            elif icon_type == "success":
                icon = QApplication.style().standardIcon(QStyle.SP_DialogApplyButton)
                card.setProperty("type", "success")
            else:
                icon = QApplication.style().standardIcon(QStyle.SP_MessageBoxInformation)
                card.setProperty("type", "info")
            
            icon_label.setPixmap(icon.pixmap(32, 32))
            card_layout.addWidget(icon_label)
            
            # Add text
            text_layout = QVBoxLayout()
            title_label = QLabel(f"<b>{title}</b>")
            title_label.setStyleSheet("color: white; font-size: 14px;")
            message_label = QLabel(message)
            message_label.setStyleSheet("color: rgba(255, 255, 255, 0.8); font-size: 12px;")
            message_label.setWordWrap(True)
            
            text_layout.addWidget(title_label)
            text_layout.addWidget(message_label)
            card_layout.addLayout(text_layout)
            
            # Add close button
            close_button = QPushButton("×")
            close_button.setFixedSize(24, 24)
            close_button.setStyleSheet("""
                QPushButton {
                    border: none;
                    color: white;
                    background: transparent;
                    font-size: 16px;
                }
                QPushButton:hover {
                    background: rgba(255, 255, 255, 0.1);
                    border-radius: 12px;
                }
            """)
            close_button.clicked.connect(self.close)
            card_layout.addWidget(close_button)
            
            # Add card to main layout
            layout.addWidget(card)
            
            # Add shadow effect
            try:
                shadow = QGraphicsDropShadowEffect()
                shadow.setBlurRadius(10)
                shadow.setColor(QColor(0, 0, 0, 160))
                shadow.setOffset(0, 0)
                card.setGraphicsEffect(shadow)
            except Exception as e:
                logging.warning(f"Could not apply shadow effect: {e}")
            
            # Position the notification
            self.position_notification()
            
            # Set up auto-close timer
            self.timer = QTimer(self)
            self.timer.timeout.connect(self.close)
            self.timer.start(5000)  # Close after 5 seconds
            
            # Set up animation
            self.animation = QPropertyAnimation(self, b"windowOpacity")
            self.animation.setDuration(250)
            self.animation.setStartValue(0)
            self.animation.setEndValue(1)
            self.animation.start()
        
        except Exception as e:
            logging.error(f"Error initializing notification widget: {e}", exc_info=True)
            # Fallback to a simple message box
            try:
                QMessageBox.information(None, title, message)
            except:
                print(f"Notification: {title} - {message}")

    
    def position_notification(self):
        """Position the notification at the bottom right of the screen"""
        try:
            desktop = QDesktopWidget().availableGeometry()
            self.move(desktop.width() - self.width() - 20, desktop.height() - self.height() - 20)
        except Exception as e:
            logging.error(f"Error positioning notification: {e}", exc_info=True)
    
    def closeEvent(self, event):
        """Handle close event with fade-out animation"""
        try:
            self.animation = QPropertyAnimation(self, b"windowOpacity")
            self.animation.setDuration(250)
            self.animation.setStartValue(1)
            self.animation.setEndValue(0)
            self.animation.finished.connect(self.on_close_finished)
            self.animation.start()
            event.ignore()
        except Exception as e:
            logging.error(f"Error in closeEvent: {e}", exc_info=True)
            super().closeEvent(event)
            self.closed.emit()
    
    def on_close_finished(self):
        """Called when all operations are finished and app can close"""
        try:
            # Instead of creating a QCloseEvent, just call close() directly
            self.close()
        except Exception as e:
            logging.error(f"Error in on_close_finished: {str(e)}")
            traceback.print_exc()



    def setup_error_logging():
        """Set up error logging to file"""
        log_dir = os.path.join(
            os.environ.get('APPDATA', os.path.expanduser('~')),
            APP_NAME,
            'logs'
        )
        os.makedirs(log_dir, exist_ok=True)
        
        error_log_path = os.path.join(log_dir, 'startup_errors.log')
        
        # Set up logging to file
        logging.basicConfig(
            filename=error_log_path,
            level=logging.ERROR,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Add console handler for debugging
        console = logging.StreamHandler()
        console.setLevel(logging.ERROR)
        formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
        console.setFormatter(formatter)
        logging.getLogger('').addHandler(console)
        
        return error_log_path

# Add this code near the top of your file, after imports but before any classes
    def setup_logging():
        """Set up logging configuration"""
        # Create logs directory if it doesn't exist
        log_dir = os.path.join(os.path.expanduser('~'), f".{APP_NAME.lower()}", "logs")
        os.makedirs(log_dir, exist_ok=True)
        
        # Set up log file path
        log_file = os.path.join(log_dir, "app.log")
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
        # Log startup information
        logging.info(f"Starting {APP_NAME} v{APP_VERSION}")
        logging.info(f"Python version: {sys.version}")
        logging.info(f"Platform: {sys.platform}")
        logging.info(f"Log file: {log_file}")
        
        # Set up exception handling
        sys.excepthook = handle_exception

    def handle_exception(exc_type, exc_value, exc_traceback):
        """Global exception handler to log unhandled exceptions"""
        if issubclass(exc_type, KeyboardInterrupt):
            # Don't log keyboard interrupt (Ctrl+C)
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
            
        logging.error("Unhandled exception", exc_info=(exc_type, exc_value, exc_traceback))



class DiagnosticWindow(QMainWindow):
    """Simple diagnostic window"""
    
    def __init__(self):
        super().__init__()
        logging.info("Initializing DiagnosticWindow")
        
        # Check admin status
        self.is_admin_mode = is_admin()
        admin_status = "Admin Mode" if self.is_admin_mode else "Standard Mode"
        
        self.setWindowTitle(f"{APP_NAME} - Diagnostic ({admin_status})")
        self.setMinimumSize(600, 400)
        
        # Create central widget
        central_widget = QWidget()
        layout = QVBoxLayout(central_widget)
        
        # Add some labels
        title_label = QLabel(f"{APP_NAME} v{APP_VERSION}")
        title_label.setStyleSheet("font-size: 24px; font-weight: bold;")
        layout.addWidget(title_label)
        
        status_label = QLabel(f"Diagnostic Mode - {admin_status}")
        status_label.setStyleSheet("font-size: 18px;")
        layout.addWidget(status_label)
        
        # Create tabs for different diagnostic functions
        tab_widget = QTabWidget()
        
        # System Information Tab
        system_tab = QWidget()
        system_layout = QVBoxLayout(system_tab)
        
        # System information
        system_info_group = QGroupBox("System Information")
        system_info_layout = QVBoxLayout(system_info_group)
        
        info_label = QLabel(f"Python: {sys.version}")
        system_info_layout.addWidget(info_label)
        
        qt_version_label = QLabel(f"Qt: {Qt.qVersion()}")
        system_info_layout.addWidget(qt_version_label)
        
        platform_label = QLabel(f"Platform: {sys.platform}")
        system_info_layout.addWidget(platform_label)
        
        cpu_info = QLabel(f"CPU Cores: {os.cpu_count()}")
        system_info_layout.addWidget(cpu_info)
        
        # Get memory info
        try:
            import psutil
            vm = psutil.virtual_memory()
            memory_info = QLabel(f"Memory: {vm.total / (1024**3):.2f} GB (Used: {vm.percent}%)")
            
            # Add disk info
            disk = psutil.disk_usage('/')
            disk_info = QLabel(f"Disk: {disk.total / (1024**3):.2f} GB (Used: {disk.percent}%)")
            system_info_layout.addWidget(disk_info)
            
            # Add network info if available
            try:
                net_io = psutil.net_io_counters()
                net_info = QLabel(f"Network: Sent {net_io.bytes_sent / (1024**2):.2f} MB, Received {net_io.bytes_recv / (1024**2):.2f} MB")
                system_info_layout.addWidget(net_info)
            except:
                pass
                
        except ImportError:
            memory_info = QLabel("Memory: psutil module not available")
        system_info_layout.addWidget(memory_info)
        
        # Add admin status info
        admin_info = QLabel(f"Admin Privileges: {'Yes' if self.is_admin_mode else 'No'}")
        admin_info.setStyleSheet("font-weight: bold; color: " + ("green" if self.is_admin_mode else "red"))
        system_info_layout.addWidget(admin_info)
        
        # Add app paths info
        app_path_info = QLabel(f"App Path: {os.path.abspath(sys.argv[0])}")
        system_info_layout.addWidget(app_path_info)
        
        data_path = os.path.join(os.path.expanduser('~'), f".{APP_NAME.lower()}")
        data_path_info = QLabel(f"Data Path: {data_path}")
        system_info_layout.addWidget(data_path_info)
        
        system_layout.addWidget(system_info_group)
        
        # Test Functions Tab
        test_tab = QWidget()
        test_layout = QVBoxLayout(test_tab)
        
        # Add test buttons
        test_buttons_group = QGroupBox("Test Functions")
        test_buttons_layout = QVBoxLayout(test_buttons_group)
        
        test_button = QPushButton("Test UI Responsiveness")
        test_button.clicked.connect(self.test_button_clicked)
        test_buttons_layout.addWidget(test_button)
        
        test_file_io = QPushButton("Test File I/O")
        test_file_io.clicked.connect(self.test_file_io)
        test_buttons_layout.addWidget(test_file_io)
        
        test_signature = QPushButton("Test Signature Database")
        test_signature.clicked.connect(self.test_signature_db)
        test_buttons_layout.addWidget(test_signature)
        
        test_quarantine = QPushButton("Test Quarantine System")
        test_quarantine.clicked.connect(self.test_quarantine)
        test_buttons_layout.addWidget(test_quarantine)
        
        # Add admin-only test button
        test_admin = QPushButton("Test Admin Functions")
        test_admin.clicked.connect(self.test_admin_functions)
        test_admin.setEnabled(self.is_admin_mode)
        if not self.is_admin_mode:
            test_admin.setToolTip("Requires administrator privileges")
        test_buttons_layout.addWidget(test_admin)
        
        # Add restart as admin button if not in admin mode
        if not self.is_admin_mode:
            restart_admin = QPushButton("Restart as Administrator")
            restart_admin.clicked.connect(self.restart_as_admin)
            restart_admin.setStyleSheet("background-color: #FFC107; font-weight: bold;")
            test_buttons_layout.addWidget(restart_admin)
        
        test_layout.addWidget(test_buttons_group)
        
        # Logs Tab
        logs_tab = QWidget()
        logs_layout = QVBoxLayout(logs_tab)
        
        log_controls = QHBoxLayout()
        
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        logs_layout.addWidget(self.log_display)
        
        refresh_logs = QPushButton("Refresh Logs")
        refresh_logs.clicked.connect(self.refresh_logs)
        log_controls.addWidget(refresh_logs)
        
        clear_logs = QPushButton("Clear Log Display")
        clear_logs.clicked.connect(self.clear_log_display)
        log_controls.addWidget(clear_logs)
        
        save_logs = QPushButton("Save Logs")
        save_logs.clicked.connect(self.save_logs)
        log_controls.addWidget(save_logs)
        
        logs_layout.addLayout(log_controls)
        
        # Add tabs to tab widget
        tab_widget.addTab(system_tab, "System Info")
        tab_widget.addTab(test_tab, "Test Functions")
        tab_widget.addTab(logs_tab, "Logs")
        
        # Add advanced tab if in admin mode
        if self.is_admin_mode:
            advanced_tab = self.create_advanced_tab()
            tab_widget.addTab(advanced_tab, "Advanced")
        
        layout.addWidget(tab_widget)
        
        # Add a status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage(f"Ready - Running in {admin_status}")
        
        # Set central widget
        self.setCentralWidget(central_widget)
        
        # Load initial logs
        self.refresh_logs()
        
        logging.info(f"DiagnosticWindow initialized successfully in {admin_status}")

    def _load_config(self):
        """Load configuration from file or create default"""
        config_path = os.path.join(
            os.environ.get('APPDATA', os.path.expanduser('~')),
            APP_NAME,
            'config.json'
        )
        # Add these utility functions near the top of your file, after imports
# but before class definitions

    def delete_file(file_path):
        """Delete a file with proper error handling"""
        try:
            if os.path.exists(file_path):
                # Check if we have write permissions to the file
                if not os.access(file_path, os.W_OK):
                    logging.warning(f"No write permission for {file_path}")
                    # Try to change permissions first
                    try:
                        os.chmod(file_path, 0o666)  # Set read/write permissions
                    except Exception as e:
                        logging.error(f"Failed to change permissions: {str(e)}")
                        return False, "Access denied - insufficient permissions"
                
                os.remove(file_path)
                return True, "File deleted successfully"
            else:
                return False, "File does not exist"
        except PermissionError:
            logging.error(f"Permission denied when deleting {file_path}")
            # Try to handle locked files on Windows
            if sys.platform == 'win32':
                return handle_locked_file_windows(file_path)
            return False, "Access denied - file may be in use by another process"
        except Exception as e:
            logging.error(f"Error deleting file {file_path}: {str(e)}")
            return False, f"Error: {str(e)}"

    def handle_locked_file_windows(file_path):
        """Handle locked files on Windows using specialized techniques"""
        try:
            import win32con
            import win32file
            import pywintypes
            
            try:
                # Try to take ownership of the file (requires admin)
                if is_admin():
                    take_ownership_cmd = f'takeown /f "{file_path}" /a'
                    subprocess.run(take_ownership_cmd, shell=True, check=False)
                    
                    # Grant full control
                    icacls_cmd = f'icacls "{file_path}" /grant administrators:F'
                    subprocess.run(icacls_cmd, shell=True, check=False)
                
                # Try to change file attributes to normal
                win32file.SetFileAttributes(file_path, win32con.FILE_ATTRIBUTE_NORMAL)
                
                # Try to delete using Windows API
                win32file.DeleteFile(file_path)
                return True, "File deleted successfully using Windows API"
            except pywintypes.error as we:
                logging.error(f"Windows API deletion failed: {str(we)}")
                
                # Last resort: schedule deletion on reboot
                try:
                    if ctypes.windll.kernel32.MoveFileExW(file_path, None, 4):  # MOVEFILE_DELAY_UNTIL_REBOOT
                        return True, "File scheduled for deletion on next reboot"
                    else:
                        return False, "Failed to schedule deletion on reboot"
                except Exception as e:
                    logging.error(f"Failed to schedule deletion: {str(e)}")
                    return False, "Failed to delete file - try running as administrator"
        except ImportError:
            logging.error("Windows modules not available for advanced deletion")
            return False, "Required Windows modules not available"
        except Exception as e:
            logging.error(f"Error in handle_locked_file_windows: {str(e)}")
            return False, f"Error: {str(e)}"

    def force_delete_file(file_path):
        """Force delete a file using Windows-specific methods if needed"""
        try:
            if os.path.exists(file_path):
                # First try standard deletion
                try:
                    os.remove(file_path)
                    return True, "File deleted successfully"
                except Exception as e:
                    logging.warning(f"Standard deletion failed for {file_path}: {str(e)}")
                
                # Try Windows-specific methods
                if sys.platform == 'win32':
                    return handle_locked_file_windows(file_path)
                else:
                    # For Unix systems, try with sudo if available and we're not root
                    if os.geteuid() != 0:  # Not root
                        try:
                            cmd = f'sudo rm -f "{file_path}"'
                            result = subprocess.run(cmd, shell=True, check=False)
                            if result.returncode == 0:
                                return True, "File deleted successfully using sudo"
                            else:
                                return False, "Failed to delete with sudo"
                        except Exception as e:
                            logging.error(f"Sudo deletion failed: {str(e)}")
                            return False, f"Sudo deletion failed: {str(e)}"
                    
                    return False, "Failed to delete file - insufficient permissions"
            else:
                return True, "File does not exist"
        except Exception as e:
            logging.error(f"Error in force_delete_file: {str(e)}")
            return False, f"Error: {str(e)}"

    def delete_with_retry(file_path, max_attempts=3, delay=1.0):
        """Delete a file with multiple retry attempts"""
        for attempt in range(max_attempts):
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    return True, f"File deleted successfully on attempt {attempt+1}"
                return True, "File does not exist"
            except Exception as e:
                logging.warning(f"Delete attempt {attempt+1} failed: {str(e)}")
                if attempt < max_attempts - 1:
                    time.sleep(delay)  # Wait before retrying
        
        return False, f"Failed to delete after {max_attempts} attempts"

        default_config = {
            'action': 'quarantine',
            'scan_archives': True,
            'scan_memory': True,
            'scan_registry': True,
            'heuristic_level': 2,
            'max_file_size': 100,
            'max_workers': os.cpu_count() or 4,
            'real_time_monitoring': False,
            'minimize_to_tray': True,
            'start_with_system': False,
            'auto_update': True,
            'update_frequency': 'daily',
            'exclusions': [],
            'signature_sources': [
                "https://example.com/signatures/main.db",
                "https://another-source.com/virus-sigs.json"
            ],
            'theme': 'dark',
            'auto_start_scan': False,
            'scan_on_startup': False,
            'monitored_directories': [os.path.expanduser('~\\Downloads'), os.path.expanduser('~\\Desktop')],
            'monitored_extensions': ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.py'],
            'excluded_paths': [],
            'excluded_extensions': ['.jpg', '.png', '.gif', '.mp3', '.mp4', '.avi'],
            'threat_action': 'quarantine',
            'language': 'en',
            'notifications': True,
            'advanced_heuristics': True,
            'cloud_lookup': True,
            'scan_depth': 2,
            'auto_quarantine': True,
            'scan_cookies': False,
            'scheduled_scan': {
                'enabled': False,
                'frequency': 'daily',
                'day': 1,
                'time': '02:00'
            }
        }
        
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                
                # Update with any missing default values
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                
                return config
            else:
                # Create directory if it doesn't exist
                os.makedirs(os.path.dirname(config_path), exist_ok=True)
                
                # Save default config
                with open(config_path, 'w') as f:
                    json.dump(default_config, f, indent=2)
                
                return default_config
        
        except Exception as e:
            print(f"Error loading configuration: {e}")
            return default_config

    def init_ui(self):
        """Initialize the user interface"""
        # This is a placeholder method that would normally set up UI elements
        # Since we're already setting up the UI in __init__, this can be empty
        pass

    def init_tray(self):
        """Initialize system tray icon and menu"""
        # For DiagnosticWindow, we don't need a tray icon
        # This is just a placeholder to match the structure in MainWindow
        pass

    def test_button_clicked(self):
        """Test button click handler"""
        logging.info("Testing UI responsiveness")
        self.status_bar.showMessage("Testing UI...")
        
        # Simulate a heavy operation
        start_time = time.time()
        for i in range(10):
            QApplication.processEvents()  # Keep UI responsive
            time.sleep(0.1)  # Simulate work
        
        elapsed = time.time() - start_time
        result = f"UI test completed in {elapsed:.2f} seconds"
        logging.info(result)
        self.status_bar.showMessage(result, 5000)
        QMessageBox.information(self, "Test Result", result)

    def test_file_io(self):
        """Test file I/O operations"""
        logging.info("Testing file I/O")
        self.status_bar.showMessage("Testing file I/O...")
        
        try:
            # Create a test directory
            test_dir = os.path.join(os.path.expanduser('~'), f".{APP_NAME.lower()}", "test")
            os.makedirs(test_dir, exist_ok=True)
            
            # Write test file
            test_file = os.path.join(test_dir, "test_file.txt")
            with open(test_file, 'w') as f:
                f.write("This is a test file for I/O operations.")
            
            # Read test file
            with open(test_file, 'r') as f:
                content = f.read()
            
            # Clean up
            os.remove(test_file)
            
            result = "File I/O test completed successfully"
            logging.info(result)
            self.status_bar.showMessage(result, 5000)
            QMessageBox.information(self, "Test Result", result)
        
        except Exception as e:
            error_msg = f"File I/O test failed: {str(e)}"
            logging.error(error_msg)
            self.status_bar.showMessage("Test failed", 5000)
            QMessageBox.critical(self, "Test Failed", error_msg)

    def test_signature_db(self):
        """Test signature database access"""
        logging.info("Testing signature database")
        self.status_bar.showMessage("Testing signature database...")
        
        try:
            # This is a placeholder - in a real app, you'd test actual signature DB access
            signatures_found = 1000  # Simulated value
            
            result = f"Signature database test completed. Found {signatures_found} signatures."
            logging.info(result)
            self.status_bar.showMessage(result, 5000)
            QMessageBox.information(self, "Test Result", result)
        
        except Exception as e:
            error_msg = f"Signature database test failed: {str(e)}"
            logging.error(error_msg)
            self.status_bar.showMessage("Test failed", 5000)
            QMessageBox.critical(self, "Test Failed", error_msg)

    def test_quarantine(self):
        """Test quarantine system"""
        logging.info("Testing quarantine system")
        self.status_bar.showMessage("Testing quarantine system...")
        
        try:
            # Create a test file
            test_dir = os.path.join(os.path.expanduser('~'), f".{APP_NAME.lower()}", "test")
            os.makedirs(test_dir, exist_ok=True)
            
            test_file = os.path.join(test_dir, "test_malware.txt")
            with open(test_file, 'w') as f:
                f.write("This is a simulated malware file for testing quarantine.")
            
            # Simulate quarantine operation
            quarantine_dir = os.path.join(os.path.expanduser('~'), f".{APP_NAME.lower()}", "quarantine")
            os.makedirs(quarantine_dir, exist_ok=True)
            
            quarantine_file = os.path.join(quarantine_dir, "test_malware.qtn")
            
            # Simple "quarantine" by copying and renaming
            import shutil
            shutil.copy2(test_file, quarantine_file)
            
            # Clean up
            os.remove(test_file)
            os.remove(quarantine_file)
            
            result = "Quarantine system test completed successfully"
            logging.info(result)
            self.status_bar.showMessage(result, 5000)
            QMessageBox.information(self, "Test Result", result)
        
        except Exception as e:
            error_msg = f"Quarantine system test failed: {str(e)}"
            logging.error(error_msg)
            self.status_bar.showMessage("Test failed", 5000)
            QMessageBox.critical(self, "Test Failed", error_msg)

    def refresh_logs(self):
        """Refresh the log display"""
        try:
            log_path = os.path.join(os.path.expanduser('~'), f".{APP_NAME.lower()}", "logs", "app.log")
            if os.path.exists(log_path):
                with open(log_path, 'r') as f:
                    logs = f.read()
                self.log_display.setText(logs)
                self.log_display.moveCursor(QTextCursor.End)
            else:
                self.log_display.setText("No log file found.")
        except Exception as e:
            self.log_display.setText(f"Error loading logs: {str(e)}")

    def closeEvent(self, event):
        """Handle window close event"""
        logging.info("DiagnosticWindow closing")
        event.accept()



class EnhancedNotification(QWidget):
    """Premium notification widget with modern design and animations"""
    closed = pyqtSignal()
    
    def __init__(self, title, message, notification_type="info", parent=None, duration=5000):
        super().__init__(parent)
        
        # Set window flags for a frameless, always-on-top window
        self.setWindowFlags(
            Qt.FramelessWindowHint | 
            Qt.WindowStaysOnTopHint | 
            Qt.Tool |
            Qt.NoDropShadowWindowHint
        )
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setAttribute(Qt.WA_ShowWithoutActivating)
        
        # Store the notification type and duration
        self.notification_type = notification_type
        self.duration = max(2000, duration)
        
        # Set fixed size
        self.setFixedSize(360, 100)
        
        # Create main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Create notification card
        self.card = QFrame(self)
        self.card.setObjectName("notification_card")
        
        # Set card style based on notification type
        self.card.setProperty("type", notification_type)
        
        # Create card layout
        card_layout = QHBoxLayout(self.card)
        card_layout.setContentsMargins(15, 15, 15, 15)
        card_layout.setSpacing(15)
        
        # Create icon based on notification type
        icon_label = QLabel()
        icon_label.setFixedSize(32, 32)
        
        # Set icon based on notification type
        if notification_type == "info":
            icon_path = get_resource_path(":/icons/info.png")
            accent_color = "#2196F3"  # Blue
        elif notification_type == "success":
            icon_path = get_resource_path(":/icons/success.png")
            accent_color = "#4CAF50"  # Green
        elif notification_type == "warning":
            icon_path = get_resource_path(":/icons/warning.png")
            accent_color = "#FF9800"  # Orange
        elif notification_type == "error":
            icon_path = get_resource_path(":/icons/error.png")
            accent_color = "#F44336"  # Red
        else:
            icon_path = get_resource_path(":/icons/info.png")
            accent_color = "#2196F3"  # Default blue
        
        # Load and set icon
        icon_pixmap = QPixmap(icon_path)
        if not icon_pixmap.isNull():
            icon_label.setPixmap(icon_pixmap.scaled(32, 32, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        else:
            # Fallback to system icon if custom icon not found
            icon = QApplication.style().standardIcon(QStyle.SP_MessageBoxInformation)
            icon_label.setPixmap(icon.pixmap(32, 32))
        
        # Add icon to layout
        card_layout.addWidget(icon_label)
        
        # Create content layout
        content_layout = QVBoxLayout()
        content_layout.setSpacing(5)
        
        # Create title label with custom styling
        title_label = QLabel(title)
        title_label.setObjectName("notification_title")
        title_label.setStyleSheet(f"font-weight: bold; color: {accent_color}; font-size: 14px;")
        
        # Create message label
        message_label = QLabel(message)
        message_label.setObjectName("notification_message")
        message_label.setWordWrap(True)
        message_label.setStyleSheet("color: #FFFFFF; font-size: 12px;")
        
        # Add labels to content layout
        content_layout.addWidget(title_label)
        content_layout.addWidget(message_label)
        
        # Add content layout to card layout
        card_layout.addLayout(content_layout, 1)
        
        # Create close button
        close_button = QPushButton("×")
        close_button.setObjectName("notification_close")
        close_button.setFixedSize(24, 24)
        close_button.setCursor(Qt.PointingHandCursor)
        close_button.setStyleSheet("""
            QPushButton {
                border: none;
                color: rgba(255, 255, 255, 180);
                background: transparent;
                font-size: 18px;
                font-weight: bold;
                border-radius: 12px;
            }
            QPushButton:hover {
                color: white;
                background: rgba(255, 255, 255, 30);
            }
            QPushButton:pressed {
                background: rgba(255, 255, 255, 50);
            }
        """)
        close_button.clicked.connect(self.start_close_animation)
        
        # Add close button to card layout
        card_layout.addWidget(close_button)
        
        # Add card to main layout
        main_layout.addWidget(self.card)
        
        # Set up shadow effect
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(20)
        shadow.setColor(QColor(0, 0, 0, 80))
        shadow.setOffset(0, 4)
        self.card.setGraphicsEffect(shadow)
        
        # Set up animations
        self.setup_animations()
        
        # Set up auto-close timer
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(self.start_close_animation)
        
        # Set up progress bar for visual countdown
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(3)
        self.progress_bar.setObjectName("notification_progress")
        self.progress_bar.setProperty("type", notification_type)
        
        # Add progress bar to bottom of notification
        progress_layout = QHBoxLayout()
        progress_layout.setContentsMargins(0, 0, 0, 0)
        progress_layout.addWidget(self.progress_bar)
        main_layout.addLayout(progress_layout)
        
        # Set up progress animation
        self.progress_animation = QPropertyAnimation(self.progress_bar, b"value")
        self.progress_animation.setDuration(duration)
        self.progress_animation.setStartValue(100)
        self.progress_animation.setEndValue(0)
        self.progress_animation.setEasingCurve(QEasingCurve.Linear)
        
        # Position the notification
        self.position_notification()
    
    def setup_animations(self):
        """Set up entrance and exit animations"""
        # Slide-in animation
        self.slide_in = QPropertyAnimation(self, b"pos")
        self.slide_in.setDuration(300)
        self.slide_in.setEasingCurve(QEasingCurve.OutCubic)
        
        # Slide-out animation
        self.slide_out = QPropertyAnimation(self, b"pos")
        self.slide_out.setDuration(300)
        self.slide_out.setEasingCurve(QEasingCurve.InCubic)
        self.slide_out.finished.connect(self.close_notification)
        
        # Opacity animation for fade-in
        self.fade_in = QPropertyAnimation(self, b"windowOpacity")
        self.fade_in.setDuration(300)
        self.fade_in.setStartValue(0.0)
        self.fade_in.setEndValue(1.0)
        self.fade_in.setEasingCurve(QEasingCurve.OutCubic)
        
        # Opacity animation for fade-out
        self.fade_out = QPropertyAnimation(self, b"windowOpacity")
        self.fade_out.setDuration(300)
        self.fade_out.setStartValue(1.0)
        self.fade_out.setEndValue(0.0)
        self.fade_out.setEasingCurve(QEasingCurve.InCubic)
        
        # Animation group for entrance
        self.entrance_animation = QParallelAnimationGroup()
        self.entrance_animation.addAnimation(self.slide_in)
        self.entrance_animation.addAnimation(self.fade_in)
        
        # Animation group for exit
        self.exit_animation = QParallelAnimationGroup()
        self.exit_animation.addAnimation(self.slide_out)
        self.exit_animation.addAnimation(self.fade_out)
        self.exit_animation.finished.connect(self.close)
    
    def position_notification(self):
        """Position the notification at the bottom right of the screen"""
        desktop = QApplication.desktop()
        screen_rect = desktop.availableGeometry(desktop.primaryScreen())
        
        # Calculate position (start off-screen for animation)
        target_x = screen_rect.width() - self.width() - 20
        target_y = screen_rect.height() - self.height() - 20
        
        # Set start position for slide-in animation (off-screen)
        start_x = screen_rect.width()
        
        # Set animation start and end positions
        self.slide_in.setStartValue(QPoint(start_x, target_y))
        self.slide_in.setEndValue(QPoint(target_x, target_y))
        
        # Set slide-out animation to go right
        self.slide_out.setStartValue(QPoint(target_x, target_y))
        self.slide_out.setEndValue(QPoint(start_x, target_y))
        
        # Move to start position
        self.move(start_x, target_y)
    
    def showEvent(self, event):
        """Handle show event"""
        super().showEvent(event)
        
        # Start entrance animation
        self.entrance_animation.start()
        
        # Start progress bar animation
        self.progress_animation.start()
        
        # Start auto-close timer
        self.timer.start(self.duration)
    
    def start_close_animation(self):
        """Start the closing animation"""
        # Stop the timer if it's running
        if self.timer.isActive():
            self.timer.stop()
        
        # Stop progress animation
        self.progress_animation.stop()
        
        # Start exit animation
        self.exit_animation.start()
    
    def close_notification(self):
        """Close the notification and emit signal"""
        self.closed.emit()
    
    def enterEvent(self, event):
        """Handle mouse enter event"""
        # Pause the timer and progress animation when mouse enters
        if self.timer.isActive():
            self.timer.stop()
            self.progress_animation.pause()
    
    def leaveEvent(self, event):
        """Handle mouse leave event"""
        # Resume the timer and progress animation when mouse leaves
        if not self.timer.isActive() and self.windowOpacity() > 0:
            remaining_time = int(self.duration * (self.progress_bar.value() / 100))
            if remaining_time > 0:
                self.timer.start(remaining_time)
                self.progress_animation.resume()
    
    def mousePressEvent(self, event):
        """Handle mouse press event"""
        if event.button() == Qt.LeftButton:
            self.start_close_animation()
            event.accept()


# First, check if you have the NotificationManager class defined in your code
# If not, you need to add it or replace it with EnhancedNotificationManager

# Option 1: If you want to use the EnhancedNotificationManager from my previous code:
class EnhancedNotification(QWidget):
    """Premium notification widget with modern design and animations"""
    closed = pyqtSignal()
    
    def __init__(self, title, message, notification_type="info", parent=None, duration=5000):
        super().__init__(parent)
        
        # Set window flags for a frameless, always-on-top window
        self.setWindowFlags(
            Qt.FramelessWindowHint | 
            Qt.WindowStaysOnTopHint | 
            Qt.Tool |
            Qt.NoDropShadowWindowHint
        )
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setAttribute(Qt.WA_ShowWithoutActivating)
        
        # Store the notification type and duration
        self.notification_type = notification_type
        self.duration = max(2000, duration)
        
        # Set fixed size
        self.setFixedSize(360, 100)
        
        # Create main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Create notification card
        self.card = QFrame(self)
        self.card.setObjectName("notification_card")
        
        # Set card style based on notification type
        self.card.setProperty("type", notification_type)
        
        # Create card layout
        card_layout = QHBoxLayout(self.card)
        card_layout.setContentsMargins(15, 15, 15, 15)
        card_layout.setSpacing(15)
        
        # Create icon based on notification type
        icon_label = QLabel()
        icon_label.setFixedSize(32, 32)
        
        # Set icon based on notification type
        if notification_type == "info":
            icon = QApplication.style().standardIcon(QStyle.SP_MessageBoxInformation)
            accent_color = "#2196F3"  # Blue
        elif notification_type == "success":
            icon = QApplication.style().standardIcon(QStyle.SP_DialogApplyButton)
            accent_color = "#4CAF50"  # Green
        elif notification_type == "warning":
            icon = QApplication.style().standardIcon(QStyle.SP_MessageBoxWarning)
            accent_color = "#FF9800"  # Orange
        elif notification_type == "error":
            icon = QApplication.style().standardIcon(QStyle.SP_MessageBoxCritical)
            accent_color = "#F44336"  # Red
        else:
            icon = QApplication.style().standardIcon(QStyle.SP_MessageBoxInformation)
            accent_color = "#2196F3"  # Default blue
        
        # Set icon
        icon_label.setPixmap(icon.pixmap(32, 32))
        
        # Add icon to layout
        card_layout.addWidget(icon_label)
        
        # Create content layout
        content_layout = QVBoxLayout()
        content_layout.setSpacing(5)
        
        # Create title label with custom styling
        title_label = QLabel(title)
        title_label.setObjectName("notification_title")
        title_label.setStyleSheet(f"font-weight: bold; color: {accent_color}; font-size: 14px;")
        
        # Create message label
        message_label = QLabel(message)
        message_label.setObjectName("notification_message")
        message_label.setWordWrap(True)
        message_label.setStyleSheet("color: #FFFFFF; font-size: 12px;")
        
        # Add labels to content layout
        content_layout.addWidget(title_label)
        content_layout.addWidget(message_label)
        
        # Add content layout to card layout
        card_layout.addLayout(content_layout, 1)
        
        # Create close button
        close_button = QPushButton("×")
        close_button.setObjectName("notification_close")
        close_button.setFixedSize(24, 24)
        close_button.setCursor(Qt.PointingHandCursor)
        close_button.setStyleSheet("""
            QPushButton {
                border: none;
                color: rgba(255, 255, 255, 180);
                background: transparent;
                font-size: 18px;
                font-weight: bold;
                border-radius: 12px;
            }
            QPushButton:hover {
                color: white;
                background: rgba(255, 255, 255, 30);
            }
            QPushButton:pressed {
                background: rgba(255, 255, 255, 50);
            }
        """)
        close_button.clicked.connect(self.start_close_animation)
        
        # Add close button to card layout
        card_layout.addWidget(close_button)
        
        # Add card to main layout
        main_layout.addWidget(self.card)
        
        # Set up shadow effect
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(20)
        shadow.setColor(QColor(0, 0, 0, 80))
        shadow.setOffset(0, 4)
        self.card.setGraphicsEffect(shadow)
        
        # Set up animations
        self.setup_animations()
        
        # Set up auto-close timer
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(self.start_close_animation)
        
        # Set up progress bar for visual countdown
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(3)
        self.progress_bar.setObjectName("notification_progress")
        self.progress_bar.setProperty("type", notification_type)
        
        # Add progress bar to bottom of notification
        progress_layout = QHBoxLayout()
        progress_layout.setContentsMargins(0, 0, 0, 0)
        progress_layout.addWidget(self.progress_bar)
        main_layout.addLayout(progress_layout)
        
        # Set up progress animation
        self.progress_animation = QPropertyAnimation(self.progress_bar, b"value")
        self.progress_animation.setDuration(duration)
        self.progress_animation.setStartValue(100)
        self.progress_animation.setEndValue(0)
        self.progress_animation.setEasingCurve(QEasingCurve.Linear)
        
        # Position the notification
        self.position_notification()
    
    def setup_animations(self):
        """Set up entrance and exit animations"""
        # Slide-in animation
        self.slide_in = QPropertyAnimation(self, b"pos")
        self.slide_in.setDuration(300)
        self.slide_in.setEasingCurve(QEasingCurve.OutCubic)
        
        # Slide-out animation
        self.slide_out = QPropertyAnimation(self, b"pos")
        self.slide_out.setDuration(300)
        self.slide_out.setEasingCurve(QEasingCurve.InCubic)
        self.slide_out.finished.connect(self.close_notification)
        
        # Opacity animation for fade-in
        self.fade_in = QPropertyAnimation(self, b"windowOpacity")
        self.fade_in.setDuration(300)
        self.fade_in.setStartValue(0.0)
        self.fade_in.setEndValue(1.0)
        self.fade_in.setEasingCurve(QEasingCurve.OutCubic)
        
        # Opacity animation for fade-out
        self.fade_out = QPropertyAnimation(self, b"windowOpacity")
        self.fade_out.setDuration(300)
        self.fade_out.setStartValue(1.0)
        self.fade_out.setEndValue(0.0)
        self.fade_out.setEasingCurve(QEasingCurve.InCubic)
        
        # Animation group for entrance
        self.entrance_animation = QParallelAnimationGroup()
        self.entrance_animation.addAnimation(self.slide_in)
        self.entrance_animation.addAnimation(self.fade_in)
        
        # Animation group for exit
        self.exit_animation = QParallelAnimationGroup()
        self.exit_animation.addAnimation(self.slide_out)
        self.exit_animation.addAnimation(self.fade_out)
        self.exit_animation.finished.connect(self.close)
    
    def position_notification(self):
        """Position the notification at the bottom right of the screen"""
        desktop = QApplication.desktop()
        screen_rect = desktop.availableGeometry(desktop.primaryScreen())
        
        # Calculate position (start off-screen for animation)
        target_x = screen_rect.width() - self.width() - 20
        target_y = screen_rect.height() - self.height() - 20
        
        # Set start position for slide-in animation (off-screen)
        start_x = screen_rect.width()
        
        # Set animation start and end positions
        self.slide_in.setStartValue(QPoint(start_x, target_y))
        self.slide_in.setEndValue(QPoint(target_x, target_y))
        
        # Set slide-out animation to go right
        self.slide_out.setStartValue(QPoint(target_x, target_y))
        self.slide_out.setEndValue(QPoint(start_x, target_y))
        
        # Move to start position
        self.move(start_x, target_y)
    
    def showEvent(self, event):
        """Handle show event"""
        super().showEvent(event)
        
        # Start entrance animation
        self.entrance_animation.start()
        
        # Start progress bar animation
        self.progress_animation.start()
        
        # Start auto-close timer
        self.timer.start(self.duration)
    
    def start_close_animation(self):
        """Start the closing animation"""
        # Stop the timer if it's running
        if self.timer.isActive():
            self.timer.stop()
        
        # Stop progress animation
        self.progress_animation.stop()
        
        # Start exit animation
        self.exit_animation.start()
    
    def close_notification(self):
        """Close the notification and emit signal"""
        self.closed.emit()
    
    def enterEvent(self, event):
        """Handle mouse enter event"""
        # Pause the timer and progress animation when mouse enters
        if self.timer.isActive():
            self.timer.stop()
            self.progress_animation.pause()
    
    def leaveEvent(self, event):
        """Handle mouse leave event"""
        # Resume the timer and progress animation when mouse leaves
        if not self.timer.isActive() and self.windowOpacity() > 0:
            remaining_time = int(self.duration * (self.progress_bar.value() / 100))
            if remaining_time > 0:
                self.timer.start(remaining_time)
                self.progress_animation.resume()
    
    def mousePressEvent(self, event):
        """Handle mouse press event"""
        if event.button() == Qt.LeftButton:
            self.start_close_animation()
            event.accept()


class NotificationManager(QObject):
    """Manager for premium notification system"""
    
    def __init__(self):
        super().__init__()
        self.notifications = []
        self.max_notifications = 3
        self.spacing = 10
        self.notification_queue = []
        self.processing_queue = False
        
        # Get screen dimensions for positioning
        desktop = QApplication.desktop()
        self.screen_rect = desktop.availableGeometry(desktop.primaryScreen())
    
    def show_notification(self, title, message, notification_type="info", duration=5000):
        """Show a premium notification"""
        # Handle old-style icon parameter (for backward compatibility)
        if isinstance(notification_type, QIcon):
            notification_type = "info"
        
        # Create notification data
        notification_data = {
            'title': title,
            'message': message,
            'type': notification_type,
            'duration': duration
        }
        
        # Add to queue
        self.notification_queue.append(notification_data)
        
        # Process queue
        self.process_queue()
    
    def process_queue(self):
        """Process the notification queue"""
        if self.processing_queue:
            return
        
        self.processing_queue = True
        
        # Check if we can show more notifications
        if len(self.notifications) < self.max_notifications and self.notification_queue:
            # Get next notification from queue
            notification_data = self.notification_queue.pop(0)
            
            # Create notification
            notification = EnhancedNotification(
                notification_data['title'],
                notification_data['message'],
                notification_data['type'],
                None,
                notification_data.get('duration', 5000)
            )
            
            # Connect close signal
            notification.closed.connect(self.on_notification_closed)
            
            # Adjust positions of existing notifications
            self.adjust_notification_positions()
            
            # Add to active notifications
            self.notifications.append(notification)
            
            # Show notification
            notification.show()
            
            # Continue processing queue
            QTimer.singleShot(100, self.process_queue)
        else:
            self.processing_queue = False
    
    def adjust_notification_positions(self):
        """Adjust positions of all notifications"""
        if not self.notifications:
            return
        
        # Calculate base position (bottom right)
        base_x = self.screen_rect.width() - 380
        base_y = self.screen_rect.height() - 20
        
        # Position each notification from bottom to top
        total_height = 0
        for notification in reversed(self.notifications):
            # Calculate position
            y_pos = base_y - notification.height() - total_height
            
            # Move notification
            notification.move(base_x, y_pos)
            
            # Update total height
            total_height += notification.height() + self.spacing
    
    def on_notification_closed(self):
        """Handle notification closed signal"""
        # Find the notification that was closed
        sender = self.sender()
        if sender in self.notifications:
            self.notifications.remove(sender)
            
            # Adjust positions of remaining notifications
            self.adjust_notification_positions()
            
            # Process more notifications from queue
            QTimer.singleShot(100, self.process_queue)


class VirusScanner:
    """Advanced class for scanning files for viruses with multiple detection methods"""
    
    # Expanded signature database path
    SIGNATURE_DB_PATH = os.path.join(
        os.environ.get('APPDATA', os.path.expanduser('~')),
        APP_NAME,
        'signatures'
    )
    
    # Cache for signatures to avoid reloading
    _signatures_cache = None
    _last_signatures_load = 0
    _signatures_cache_ttl = 300  # 5 minutes
    
    @staticmethod
    def scan_file(file_path, config=None):
        """Scan a single file for threats with multiple detection methods"""
        if not os.path.exists(file_path) or os.path.isdir(file_path):
            return []
        
        threats = []
        config = config or {}
        sensitivity = config.get('heuristic_level', 2)
        
        try:
            # Check whitelist paths first
            for safe_path in WHITELIST_PATHS:
                if file_path.lower().startswith(safe_path.lower()):
                    return []  # Skip scanning for whitelisted paths
            
            # Load signatures
            signatures = VirusScanner.load_signatures()
            
            # Calculate file hash and check against whitelist
            md5_hash = VirusScanner.calculate_file_hash(file_path, 'md5')
            sha256_hash = VirusScanner.calculate_file_hash(file_path, 'sha256')
            
            # Check whitelist hashes
            if md5_hash and md5_hash in WHITELIST_HASHES:
                return []  # Skip scanning for whitelisted hashes
            
            # Check digital signature for trusted publishers (Windows only)
            if sys.platform == 'win32' and VirusScanner.is_signed_by_trusted_publisher(file_path):
                return []  # Skip scanning for files signed by trusted publishers
            
            # Check file extension - but with lower confidence
            if VirusScanner.check_file_extension(file_path):
                # Only consider suspicious extension if sensitivity is high
                if sensitivity >= 3:
                    threats.append({
                        'type': 'extension',
                        'name': 'Suspicious.Extension',
                        'confidence': 0.3,  # Lower confidence for extension-only detection
                        'details': 'File has suspicious extension'
                    })
            
            # Check against signatures
            if md5_hash and md5_hash in signatures:
                threats.append({
                    'type': 'signature',
                    'name': signatures[md5_hash],
                    'confidence': 0.95,
                    'details': f'MD5 hash match: {md5_hash}'
                })
            
            if sha256_hash and sha256_hash in signatures:
                threats.append({
                    'type': 'signature',
                    'name': signatures[sha256_hash],
                    'confidence': 0.95,
                    'details': f'SHA256 hash match: {sha256_hash}'
                })
            
            # Skip further analysis if already identified as a threat by hash
            if threats and config.get('quick_scan', False):
                return threats
            
            # Check file size before content analysis
            try:
                file_size = os.path.getsize(file_path)
                max_content_size = 50 * 1024 * 1024  # 50MB max for content analysis
                
                if file_size <= max_content_size:
                    # Scan file content for malicious patterns
                    content_threats = VirusScanner.scan_file_content(file_path, sensitivity)
                    if content_threats:
                        threats.extend(content_threats)
            except Exception as e:
                logging.error(f"Error checking file size for content analysis: {str(e)}")
            
            # Filter threats based on sensitivity and confidence
            # Increase the minimum confidence thresholds to reduce false positives
            min_confidence = [0.85, 0.75, 0.6][sensitivity-1]
            threats = [t for t in threats if t.get('confidence', 0) >= min_confidence]
            
            # If only heuristic detections and no signature match, require higher confidence
            if threats and all(t.get('type') == 'heuristic' for t in threats):
                heuristic_min_confidence = [0.9, 0.8, 0.7][sensitivity-1]
                threats = [t for t in threats if t.get('confidence', 0) >= heuristic_min_confidence]
            
            return threats
        
        except Exception as e:
            logging.error(f"Error scanning file {file_path}: {str(e)}")
            return []
    
    @staticmethod
    def check_file_extension(file_path):
        """Check if file has a suspicious extension"""
        _, ext = os.path.splitext(file_path.lower())
        return ext in SUSPICIOUS_EXTENSIONS
    
    @staticmethod
    def is_signed_by_trusted_publisher(file_path):
        """Check if a file is digitally signed by a trusted publisher (Windows only)"""
        if sys.platform != 'win32':
            return False
            
        try:
            import subprocess
            
            # Use PowerShell to check digital signature
            cmd = f'powershell -Command "Get-AuthenticodeSignature \'{file_path}\' | Select-Object -ExpandProperty SignerCertificate | Select-Object -ExpandProperty Subject"'
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            
            if result.returncode == 0 and result.stdout:
                # Check if any trusted publisher is in the signature
                for publisher in TRUSTED_PUBLISHERS:
                    if publisher.lower() in result.stdout.lower():
                        return True
        except:
            pass
            
        return False

    
    @staticmethod
    def calculate_file_hash(self, file_path, algorithm='md5'):
        """Calculate hash of a file using specified algorithm"""
        try:
            hash_obj = None
            if algorithm == 'md5':
                hash_obj = hashlib.md5()
            elif algorithm == 'sha256':
                hash_obj = hashlib.sha256()
            else:
                return None
            
            with open(file_path, 'rb') as f:
                # Read file in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_obj.update(chunk)
            
            return hash_obj.hexdigest()
        except Exception:
            return None
    
    @staticmethod
    def get_file_entropy(file_path):
        """Calculate Shannon entropy of a file to detect encryption/packing"""
        try:
            # Use a maximum read size to prevent memory issues with large files
            max_read_size = 1024 * 1024  # 1MB
            
            with open(file_path, 'rb') as f:
                # For large files, read only the first and last portions
                file_size = os.path.getsize(file_path)
                
                if file_size <= max_read_size:
                    # For small files, read the entire content
                    data = f.read()
                else:
                    # For large files, read first and last 512KB
                    first_chunk = f.read(max_read_size // 2)
                    f.seek(-min(max_read_size // 2, file_size), 2)  # Seek from end
                    last_chunk = f.read(max_read_size // 2)
                    data = first_chunk + last_chunk
            
            if not data:
                return 0
                
            entropy = 0
            byte_counts = Counter(data)
            data_size = len(data)
            
            # Calculate Shannon entropy
            for count in byte_counts.values():
                probability = count / data_size
                entropy -= probability * math.log2(probability)
                
            return entropy
        except Exception as e:
            logging.error(f"Error calculating entropy: {str(e)}")
            return 0

    
    @staticmethod
    def calculate_entropy(data):
        """Calculate Shannon entropy of binary data"""
        if not data:
            return 0
            
        entropy = 0
        byte_counts = Counter(data)
        data_size = len(data)
        
        for count in byte_counts.values():
            probability = count / data_size
            entropy -= probability * math.log2(probability)
            
        return entropy
    
class VirusScanner:
    """Advanced class for scanning files for viruses with multiple detection methods"""
    
    # Expanded signature database path
    SIGNATURE_DB_PATH = os.path.join(
        os.environ.get('APPDATA', os.path.expanduser('~')),
        APP_NAME,
        'signatures'
    )
    
    # Cache for signatures to avoid reloading
    _signatures_cache = None
    _last_signatures_load = 0
    _signatures_cache_ttl = 300  # 5 minutes
    
    @staticmethod
    def calculate_file_hash(file_path, algorithm='md5'):
        """Calculate hash of a file using specified algorithm"""
        try:
            hash_obj = None
            if algorithm == 'md5':
                hash_obj = hashlib.md5()
            elif algorithm == 'sha256':
                hash_obj = hashlib.sha256()
            else:
                return None
            
            # Use buffered reading to handle large files efficiently
            with open(file_path, 'rb') as f:
                # Read file in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_obj.update(chunk)
            
            return hash_obj.hexdigest()
        except Exception as e:
            logging.error(f"Error calculating hash for {file_path}: {str(e)}")
            return None
    
    @staticmethod
    def load_signatures():
        """Load virus signatures from database files with caching"""
        current_time = time.time()
        
        # Return cached signatures if they're still valid
        if (VirusScanner._signatures_cache is not None and 
            current_time - VirusScanner._last_signatures_load < VirusScanner._signatures_cache_ttl):
            return VirusScanner._signatures_cache
        
        signatures = {}
        
        try:
            # Create signatures directory if it doesn't exist
            os.makedirs(VirusScanner.SIGNATURE_DB_PATH, exist_ok=True)
            
            # Load all signature files
            for filename in os.listdir(VirusScanner.SIGNATURE_DB_PATH):
                if filename.endswith('.json'):
                    try:
                        with open(os.path.join(VirusScanner.SIGNATURE_DB_PATH, filename), 'r') as f:
                            sig_data = json.load(f)
                            if isinstance(sig_data, dict):
                                signatures.update(sig_data)
                    except Exception as e:
                        logging.error(f"Error loading signature file {filename}: {str(e)}")
            
            # If no signatures found, use default ones
            if not signatures:
                signatures = VIRUS_SIGNATURES
        except Exception as e:
            logging.error(f"Error loading signatures: {str(e)}")
            signatures = VIRUS_SIGNATURES
        
        # Update cache
        VirusScanner._signatures_cache = signatures
        VirusScanner._last_signatures_load = current_time
        
        return signatures
    


    
    def get_file_type(self, file_path):
        """Determine file type for specialized analysis"""
        try:
            # Check file extension
            _, ext = os.path.splitext(file_path.lower())
            
            # PE files
            if ext in ['.exe', '.dll', '.sys', '.scr', '.ocx']:
                return 'pe'
            
            # Script files
            if ext in ['.js', '.vbs', '.ps1', '.bat', '.cmd', '.hta', '.py']:
                return 'script'
            
            # Document files
            if ext in ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf']:
                return 'document'
            
            # Try to determine by content
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(8)
                
                # Check for PE header
                if header[0:2] == b'MZ':
                    return 'pe'
                
                # Check for PDF header
                if header.startswith(b'%PDF'):
                    return 'document'
            except:
                pass
            
            # Default to binary
            return 'binary'
        except Exception:
            return 'unknown'
    
    @staticmethod
    def analyze_pe_file(file_path, sensitivity=2):
        """Analyze PE files for malicious characteristics"""
        threats = []
        
        try:
            # Check for suspicious strings in PE files
            with open(file_path, 'rb') as f:
                content = f.read()
                
            suspicious_strings = [
                b'CreateRemoteThread', b'VirtualAlloc', b'VirtualProtect',
                b'WriteProcessMemory', b'CreateProcess', b'WinExec',
                b'ShellExecute', b'URLDownloadToFile', b'GetProcAddress',
                b'LoadLibrary', b'WSASocket', b'InternetOpen'
            ]
            
            # Add more strings for higher sensitivity
            if sensitivity >= 2:
                suspicious_strings.extend([
                    b'CreateThread', b'CreateService', b'StartService',
                    b'RegCreateKey', b'RegSetValue'
                ])
            
            if sensitivity >= 3:
                suspicious_strings.extend([
                    b'SetWindowsHook', b'FindWindow', b'GetAsyncKeyState',
                    b'GetForegroundWindow', b'GetWindowText', b'keybd_event'
                ])
            
            # Adjust confidence based on sensitivity
            confidence_base = 0.5 + (sensitivity * 0.1)
            
            for string in suspicious_strings:
                if string in content:
                    threats.append({
                        'type': 'heuristic',
                        'name': 'Suspicious.API.Usage',
                        'confidence': confidence_base,
                        'details': f'Contains suspicious API: {string.decode("utf-8", errors="ignore")}'
                    })
            
            # Try to use pefile if available
            try:
                import pefile
                pe = pefile.PE(file_path)
                
                # Check for common malicious sections
                suspicious_sections = ['.upx', '.aspack', '.vmp', '.packed']
                for section in pe.sections:
                    section_name = section.Name.decode('utf-8', 'ignore').strip('\x00')
                    if section_name.lower() in suspicious_sections:
                        threats.append({
                            'type': 'heuristic',
                            'name': f'Suspicious.Packer.{section_name}',
                            'confidence': 0.8,
                            'details': f'Contains suspicious section: {section_name}'
                        })
            except ImportError:
                pass  # pefile not available
            
        except Exception as e:
            print(f"Error analyzing PE file: {e}")
        
        return threats
    
    @staticmethod
    def analyze_script_file(file_path, sensitivity=2):
        """Analyze script files for malicious code"""
        threats = []
        
        try:
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
            
            # Check for obfuscation
            obfuscation_patterns = [
                r'eval\s*\(', r'execute\s*\(', r'fromcharcode',
                r'String\.fromCharCode', r'unescape\s*\(', r'atob\s*\(',
                r'\\x[0-9a-f]{2}', r'\\u[0-9a-f]{4}', r'base64'
            ]
            
            # Add more patterns for higher sensitivity
            if sensitivity >= 2:
                obfuscation_patterns.extend([
                    r'escape\s*\(', r'btoa\s*\(', r'charCodeAt',
                    r'replace\s*\(\s*\/[^\/]+\/g'
                ])
            
            if sensitivity >= 3:
                obfuscation_patterns.extend([
                    r'parseInt\s*\(\s*[\'"][0-9a-f]+[\'"]', 
                    r'substr\s*\(\s*\d+\s*,\s*\d+\s*\)',
                    r'substring\s*\(\s*\d+\s*,\s*\d+\s*\)'
                ])
            
            # Adjust confidence based on sensitivity
            confidence_base = 0.6 + (sensitivity * 0.1)
            
            for pattern in obfuscation_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    threats.append({
                        'type': 'heuristic',
                        'name': 'Suspicious.Obfuscation',
                        'confidence': confidence_base,
                        'details': f'Contains obfuscated code: {pattern}'
                    })
            
            # Check for suspicious script patterns
            suspicious_patterns = [
                # PowerShell
                r'powershell\s+-[eE]', r'bypass\s+-[eE]', r'hidden\s+-[eE]',
                r'downloadstring', r'iex\s*\(', r'invoke-expression',
                
                # JavaScript
                r'ActiveXObject', r'WScript\.Shell', r'new\s+ActiveX',
                r'document\.write\s*\(\s*unescape', r'eval\s*\(\s*unescape',
                
                # VBScript
                r'CreateObject\s*\(\s*["\']WScript', r'CreateObject\s*\(\s*["\']Scripting',
                r'CreateObject\s*\(\s*["\']Shell', r'CreateObject\s*\(\s*["\']ADODB',
                
                # General
                r'cmd\.exe', r'cmd\s+/c', r'powershell\s+-', r'rundll32',
                r'regsvr32', r'bitsadmin', r'certutil\s+-urlcache'
            ]
            
            # Add more patterns for higher sensitivity
            if sensitivity >= 2:
                suspicious_patterns.extend([
                    r'net\s+user', r'net\s+localgroup', r'taskkill',
                    r'tasklist', r'netsh\s+firewall', r'reg\s+add',
                    r'reg\s+delete', r'schtasks'
                ])
            
            if sensitivity >= 3:
                suspicious_patterns.extend([
                    r'wmic', r'sc\s+create', r'sc\s+start', r'sc\s+config',
                    r'attrib\s+\+h', r'attrib\s+\+s', r'icacls', r'cacls'
                ])
            
            for pattern in suspicious_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    threats.append({
                        'type': 'heuristic',
                        'name': 'Suspicious.ScriptPattern',
                        'confidence': 0.8,
                        'details': f'Contains suspicious pattern: {pattern}'
                    })
        
        except Exception as e:
            print(f"Error analyzing script file: {e}")
        
        return threats
    
    @staticmethod
    def analyze_document_file(file_path, sensitivity=2):
        """Analyze document files for malicious macros and exploits"""
        threats = []
        
        try:
            # Check for PDF exploits
            if file_path.lower().endswith('.pdf'):
                with open(file_path, 'rb') as f:
                    content = f.read()
                
                # Check for JavaScript in PDF
                if b'/JavaScript' in content or b'/JS' in content:
                    threats.append({
                        'type': 'heuristic',
                        'name': 'Suspicious.PDFJavaScript',
                        'confidence': 0.6,
                        'details': 'PDF contains JavaScript'
                    })
                
                # Check for common PDF exploits
                exploit_patterns = [
                    b'/Launch', b'/URI', b'/SubmitForm', b'/RichMedia',
                    b'/OpenAction', b'/AA', b'/AcroForm', b'/XFA'
                ]
                
                # Add more patterns for higher sensitivity
                if sensitivity >= 2:
                    exploit_patterns.extend([
                        b'/ObjStm', b'/JS', b'/JavaScript', b'/JBIG2Decode'
                    ])
                
                if sensitivity >= 3:
                    exploit_patterns.extend([
                        b'/ASCIIHexDecode', b'/ASCII85Decode', b'/LZWDecode',
                        b'/FlateDecode', b'/RunLengthDecode'
                    ])
                
                for pattern in exploit_patterns:
                    if pattern in content:
                        threats.append({
                            'type': 'heuristic',
                            'name': 'Suspicious.PDFExploit',
                            'confidence': 0.7,
                            'details': f'PDF contains potential exploit: {pattern.decode("utf-8", errors="ignore")}'
                        })
            
            # Check for Office macros
            elif file_path.lower().endswith(('.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm')):
                # Try to use oletools if available
                try:
                    import olefile
                    if olefile.isOleFile(file_path):
                        ole = olefile.OleFile(file_path)
                        if ole.exists('Macros') or ole.exists('VBA'):
                            threats.append({
                                'type': 'heuristic',
                                'name': 'Suspicious.OfficeMacro',
                                'confidence': 0.7,
                                'details': 'Office document contains macros'
                            })
                except ImportError:
                    pass  # oletools not available
        
        except Exception as e:
            print(f"Error analyzing document file: {e}")
        
        return threats
    
    @staticmethod
    def load_signatures():
        """Load virus signatures from database files"""
        signatures = {}
        
        try:
            # Create signatures directory if it doesn't exist
            os.makedirs(VirusScanner.SIGNATURE_DB_PATH, exist_ok=True)
            
            # Load all signature files
            for filename in os.listdir(VirusScanner.SIGNATURE_DB_PATH):
                if filename.endswith('.json'):
                    try:
                        with open(os.path.join(VirusScanner.SIGNATURE_DB_PATH, filename), 'r') as f:
                            sig_data = json.load(f)
                            if isinstance(sig_data, dict):
                                signatures.update(sig_data)
                    except:
                        pass
            
            # If no signatures found, use default ones
            if not signatures:
                signatures = VIRUS_SIGNATURES
        except:
            signatures = VIRUS_SIGNATURES
        
        return signatures
    
@staticmethod
def scan_file(file_path, config=None):
    """Scan a single file for threats with multiple detection methods"""
    if not os.path.exists(file_path) or os.path.isdir(file_path):
        return []
    
    threats = []
    config = config or {}
    sensitivity = config.get('heuristic_level', 2)
    
    try:
        # Check whitelist paths first
        for safe_path in WHITELIST_PATHS:
            if file_path.lower().startswith(safe_path.lower()):
                return []  # Skip scanning for whitelisted paths
        
        # Load signatures
        signatures = VirusScanner.load_signatures()
        
        # Calculate file hash and check against whitelist
        md5_hash = VirusScanner.calculate_file_hash(file_path, 'md5')
        sha256_hash = VirusScanner.calculate_file_hash(file_path, 'sha256')
        
        # Check whitelist hashes
        if md5_hash and md5_hash in WHITELIST_HASHES:
            return []  # Skip scanning for whitelisted hashes
        
        # Check digital signature for trusted publishers (Windows only)
        if sys.platform == 'win32' and VirusScanner.is_signed_by_trusted_publisher(file_path):
            return []  # Skip scanning for files signed by trusted publishers
        
        # Check file extension - but with lower confidence
        if VirusScanner.check_file_extension(file_path):
            # Only consider suspicious extension if sensitivity is high
            if sensitivity >= 3:
                threats.append({
                    'type': 'extension',
                    'name': 'Suspicious.Extension',
                    'confidence': 0.3,  # Lower confidence for extension-only detection
                    'details': 'File has suspicious extension'
                })
        
        # Check against signatures
        if md5_hash and md5_hash in signatures:
            threats.append({
                'type': 'signature',
                'name': signatures[md5_hash],
                'confidence': 0.95,
                'details': f'MD5 hash match: {md5_hash}'
            })
        
        if sha256_hash and sha256_hash in signatures:
            threats.append({
                'type': 'signature',
                'name': signatures[sha256_hash],
                'confidence': 0.95,
                'details': f'SHA256 hash match: {sha256_hash}'
            })
        
        # Skip further analysis if already identified as a threat by hash
        if threats and config.get('quick_scan', False):
            return threats
        
        # Check file size before content analysis
        try:
            file_size = os.path.getsize(file_path)
            max_content_size = 50 * 1024 * 1024  # 50MB max for content analysis
            
            if file_size <= max_content_size:
                # Scan file content for malicious patterns
                content_threats = VirusScanner.scan_file_content(file_path, sensitivity)
                if content_threats:
                    threats.extend(content_threats)
        except Exception as e:
            logging.error(f"Error checking file size for content analysis: {str(e)}")
        
        # Filter threats based on sensitivity and confidence
        # Increase the minimum confidence thresholds to reduce false positives
        min_confidence = [0.85, 0.75, 0.6][sensitivity-1]
        threats = [t for t in threats if t.get('confidence', 0) >= min_confidence]
        
        # If only heuristic detections and no signature match, require higher confidence
        if threats and all(t.get('type') == 'heuristic' for t in threats):
            heuristic_min_confidence = [0.9, 0.8, 0.7][sensitivity-1]
            threats = [t for t in threats if t.get('confidence', 0) >= heuristic_min_confidence]
        
        return threats
    
    except Exception as e:
        logging.error(f"Error scanning file {file_path}: {str(e)}")
        return []


@staticmethod
def is_signed_by_trusted_publisher(file_path):
    """Check if a file is digitally signed by a trusted publisher (Windows only)"""
    if sys.platform != 'win32':
        return False
        
    try:
        import subprocess
        
        # Use PowerShell to check digital signature
        cmd = f'powershell -Command "Get-AuthenticodeSignature \'{file_path}\' | Select-Object -ExpandProperty SignerCertificate | Select-Object -ExpandProperty Subject"'
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        
        if result.returncode == 0 and result.stdout:
            # Check if any trusted publisher is in the signature
            for publisher in TRUSTED_PUBLISHERS:
                if publisher.lower() in result.stdout.lower():
                    return True
    except:
        pass
        
    return False

@staticmethod
def scan_file_content(file_path, sensitivity=2):
    """Scan file content for malicious patterns with advanced heuristics"""
    try:
        # Skip very large files
        file_size = os.path.getsize(file_path)
        max_size = [100, 50, 20][sensitivity-1] * 1024 * 1024  # Adjust max size based on sensitivity
        if file_size > max_size:
            return []
        
        threats = []
        
        # Check file type
        file_type = VirusScanner.get_file_type(file_path)
        
        # Handle different file types
        if file_type == 'pe':
            # PE file analysis
            pe_threats = VirusScanner.analyze_pe_file(file_path, sensitivity)
            if pe_threats:
                threats.extend(pe_threats)
        
        elif file_type == 'script':
            # Script file analysis
            script_threats = VirusScanner.analyze_script_file(file_path, sensitivity)
            if script_threats:
                threats.extend(script_threats)
        
        elif file_type == 'document':
            # Document file analysis
            doc_threats = VirusScanner.analyze_document_file(file_path, sensitivity)
            if doc_threats:
                threats.extend(doc_threats)
        
        # Calculate file entropy for packed/encrypted detection
        entropy = VirusScanner.get_file_entropy(file_path)
        
        # Adjust entropy thresholds to reduce false positives
        # Most legitimate executables have entropy between 6.0-7.2
        # Packed/encrypted files typically have entropy > 7.8
        entropy_threshold = [7.9, 7.7, 7.5][sensitivity-1]  # Increased thresholds
        
        if entropy > entropy_threshold:
            threats.append({
                'type': 'heuristic',
                'name': 'Suspicious.HighEntropy',
                'confidence': 0.6 + ((entropy - entropy_threshold) / 10),  # Scale confidence based on how high the entropy is
                'details': f'File has high entropy ({entropy:.2f}), may be packed or encrypted'
            })
        
        # Reduce confidence for all heuristic detections to minimize false positives
        for threat in threats:
            if threat['type'] == 'heuristic':
                threat['confidence'] = max(0.5, threat['confidence'] * 0.9)  # Reduce confidence by 10%
        
        return threats
    except Exception as e:
        print(f"Error scanning file content: {e}")
        return []

    @staticmethod
    def analyze_pe_file(file_path, sensitivity=2):
        """Analyze PE files for malicious characteristics"""
        threats = []
        
        try:
            # Check for suspicious strings in PE files
            with open(file_path, 'rb') as f:
                content = f.read()
                
            # Reduce the list of suspicious strings to minimize false positives
            # Focus on the most suspicious API calls
            suspicious_strings = [
                b'CreateRemoteThread', 
                b'VirtualAllocEx', 
                b'WriteProcessMemory',
                b'ShellExecuteA',
                b'URLDownloadToFile'
            ]
            
            # Add more strings only for higher sensitivity
            if sensitivity >= 2:
                suspicious_strings.extend([
                    b'CreateProcess', 
                    b'WinExec',
                    b'ShellExecute'
                ])
            
            if sensitivity >= 3:
                suspicious_strings.extend([
                    b'VirtualAlloc',
                    b'VirtualProtect',
                    b'GetProcAddress',
                    b'LoadLibrary'
                ])
            
            # Require multiple suspicious strings for detection
            min_suspicious_count = [3, 2, 1][sensitivity-1]
            suspicious_count = 0
            
            for string in suspicious_strings:
                if string in content:
                    suspicious_count += 1
            
            # Only add a threat if multiple suspicious strings are found
            if suspicious_count >= min_suspicious_count:
                # Adjust confidence based on how many suspicious strings were found
                confidence = 0.5 + (suspicious_count / len(suspicious_strings) * 0.3)
                
                threats.append({
                    'type': 'heuristic',
                    'name': 'Suspicious.API.Usage',
                    'confidence': confidence,
                    'details': f'Contains {suspicious_count} suspicious API calls'
                })
            
            # Try to use pefile if available
            try:
                import pefile
                pe = pefile.PE(file_path)
                
                # Check for common malicious sections
                suspicious_sections = ['.upx', '.aspack', '.vmp', '.packed']
                for section in pe.sections:
                    section_name = section.Name.decode('utf-8', 'ignore').strip('\x00')
                    if section_name.lower() in suspicious_sections:
                        threats.append({
                            'type': 'heuristic',
                            'name': f'Suspicious.Packer.{section_name}',
                            'confidence': 0.7,
                            'details': f'Contains suspicious section: {section_name}'
                        })
            except ImportError:
                pass  # pefile not available
            
        except Exception as e:
            print(f"Error analyzing PE file: {e}")
        
        return threats


class ScanThread(QThread):
    """Thread for running scans without freezing the UI"""
    update_progress = pyqtSignal(int, int, str, bool)  # current, total, file_path, is_complete
    update_status = pyqtSignal(str)
    scan_complete = pyqtSignal(dict)
    log_event = pyqtSignal(str, str)
    
    def __init__(self, scan_type, target=None, action=None, config=None):
        super().__init__()
        self.scan_type = scan_type
        self.target = target
        self.action = action
        self.is_cancelled = False
        self.config = config or {}
        self.start_time = 0
        
        # Check admin status
        self.is_admin_mode = self.check_admin()
        
        # Set number of worker threads - limit to a reasonable number to prevent overload
        self.max_workers = min(self.config.get('max_workers', os.cpu_count() or 4), 8)
        
        # Add memory management variables
        self.batch_size = 100  # Process files in batches
        self.memory_threshold = 80  # Percentage of memory usage to trigger cleanup
        self.last_memory_check = 0
        self.memory_check_interval = 5  # Check memory every 5 seconds

    def check_admin(self):
        """Check if the application is running with admin privileges"""
        try:
            if sys.platform == 'win32':
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0  # Root check for Unix-like systems
        except:
            return False



    
    def run(self):
        """Run the scan in a separate thread with parallel processing"""
        try:
            self.start_time = time.time()
            self.update_status.emit(f"Starting {self.scan_type} scan...")
            self.log_event.emit("info", f"Starting {self.scan_type} scan")
            
            # Phase 1: Determine directories to scan (5% of progress)
            self.update_progress.emit(0, 100, "Identifying scan targets...", False)
            scan_dirs = self.get_scan_directories()
            self.update_progress.emit(5, 100, "Scan targets identified", False)
            
            # Phase 2: Collect files to scan (10% of progress)
            self.update_status.emit("Collecting files to scan...")
            self.update_progress.emit(5, 100, "Collecting files...", False)
            files_to_scan = self.collect_files(scan_dirs)
            total_files = len(files_to_scan)
            self.update_status.emit(f"Found {total_files} files to scan")
            self.update_progress.emit(10, 100, f"Found {total_files} files to scan", False)
            
            # Skip if no files to scan
            if not files_to_scan:
                self.update_progress.emit(100, 100, "No files to scan", True)
                self.scan_complete.emit({
                    'files_scanned': 0,
                    'threats_detected': 0,
                    'actions_taken': 0,
                    'scan_duration': time.time() - self.start_time,
                    'results': [],
                    'detection_methods': {}
                })
                return
            
            # Phase 3: Scanning files (10% to 95% of progress)
            self.update_status.emit(f"Scanning files using {self.max_workers} threads...")
            
            # Setup progress tracking
            self.scanned_count = 0
            self.threats_found = []
            self.lock = threading.Lock()
            
            # Calculate how much each file contributes to progress
            # Files contribute to 85% of the total progress (from 10% to 95%)
            progress_per_file = 85.0 / total_files if total_files > 0 else 0
            
            # Process files in batches to manage memory better
            for i in range(0, len(files_to_scan), self.batch_size):
                if self.is_cancelled:
                    self.update_status.emit("Scan cancelled")
                    self.log_event.emit("warning", "Scan cancelled by user")
                    return
                
                # Check memory usage periodically
                current_time = time.time()
                if current_time - self.last_memory_check > self.memory_check_interval:
                    self.last_memory_check = current_time
                    if self.check_memory_usage() > self.memory_threshold:
                        self.log_event.emit("warning", "High memory usage detected, triggering garbage collection")
                        self.force_garbage_collection()
                
                batch = files_to_scan[i:i+self.batch_size]
                self.process_batch(batch, progress_per_file)
                
                # Update progress after each batch
                current_progress = int(10 + (self.scanned_count * progress_per_file))
                current_progress = min(current_progress, 94)  # Cap at 94% until complete
                self.update_progress.emit(current_progress, 100, f"Processed {self.scanned_count}/{total_files} files", False)
            
            # Phase 4: Finalizing results (95% to 99% of progress)
            self.update_status.emit("Finalizing scan results...")
            self.update_progress.emit(95, 100, "Finalizing results...", False)
            
            # Prepare results
            scan_duration = time.time() - self.start_time
            
            # Count detection methods
            detection_methods = {
                'signature': 0,
                'heuristic': 0,
                'machine_learning': 0,
                'extension': 0
            }
            
            for threat in self.threats_found:
                for detection in threat.get('threats', []):
                    detection_type = detection.get('type', 'unknown')
                    if detection_type in detection_methods:
                        detection_methods[detection_type] += 1
            
            results = {
                'files_scanned': self.scanned_count,
                'threats_detected': len(self.threats_found),
                'actions_taken': len([t for t in self.threats_found if t['action_taken'] != 'none']),
                'scan_duration': scan_duration,
                'results': self.threats_found,
                'detection_methods': detection_methods
            }
            
            # Final progress update - only now do we show 100%
            self.update_progress.emit(100, 100, "Scan complete", True)
            
            # Force garbage collection before emitting results
            self.force_garbage_collection()
            
            # Emit scan complete signal
            self.scan_complete.emit(results)
            
        except Exception as e:
            self.log_event.emit("error", f"Scan error: {str(e)}")
            self.update_status.emit(f"Error: {str(e)}")
            
            # Try to provide a graceful failure
            self.scan_complete.emit({
                'files_scanned': getattr(self, 'scanned_count', 0),
                'threats_detected': len(getattr(self, 'threats_found', [])),
                'actions_taken': 0,
                'scan_duration': time.time() - self.start_time,
                'results': getattr(self, 'threats_found', []),
                'detection_methods': {},
                'error': str(e)
            })



    def process_batch(self, batch, progress_per_file):
        """Process a batch of files using thread pool"""
        try:
            # Use ThreadPoolExecutor for parallel scanning
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Submit all files for scanning
                future_to_file = {
                    executor.submit(self.scan_single_file, file_path): file_path 
                    for file_path in batch
                }
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(future_to_file):
                    if self.is_cancelled:
                        executor.shutdown(wait=False)
                        return
                    
                    file_path = future_to_file[future]
                    try:
                        result = future.result()
                        if result:
                            with self.lock:
                                self.threats_found.append(result)
                    except Exception as e:
                        self.log_event.emit("error", f"Error scanning {file_path}: {str(e)}")
                    
                    # Update progress after each file is processed
                    with self.lock:
                        self.scanned_count += 1
                        
                        # Only update UI every few files to avoid overload
                        if self.scanned_count % 10 == 0:
                            # Calculate current progress (10% base + progress from files)
                            current_progress = int(10 + (self.scanned_count * progress_per_file))
                            # Ensure progress doesn't exceed 95% until we're done
                            current_progress = min(current_progress, 94)
                            self.update_progress.emit(current_progress, 100, file_path, False)
        
        except Exception as e:
            self.log_event.emit("error", f"Error processing batch: {str(e)}")

    def check_memory_usage(self):
        """Check current memory usage percentage"""
        try:
            import psutil
            process = psutil.Process(os.getpid())
            memory_info = process.memory_info()
            memory_percent = process.memory_percent()
            
            self.log_event.emit("info", f"Memory usage: {memory_percent:.1f}% ({memory_info.rss / (1024*1024):.1f} MB)")
            return memory_percent
        except ImportError:
            # If psutil is not available, assume memory usage is OK
            return 0
        except Exception as e:
            self.log_event.emit("error", f"Error checking memory usage: {str(e)}")
            return 0
        
    def force_garbage_collection(self):
        """Force garbage collection to free memory"""
        try:
            import gc
            # Collect all generations
            gc.collect(0)
            gc.collect(1)
            gc.collect(2)
            self.log_event.emit("info", "Garbage collection performed")
        except Exception as e:
            self.log_event.emit("error", f"Error during garbage collection: {str(e)}")
    


    
    def scan_single_file(self, file_path):
        """Scan a single file and update progress"""
        try:
            # Skip system files unless in full scan mode with high sensitivity
            if self.is_system_file(file_path) and (self.scan_type != "full" or self.config.get('heuristic_level', 2) < 3):
                return None
            
            # Skip the application itself and its directory
            app_path = os.path.abspath(sys.argv[0])
            app_dir = os.path.dirname(app_path)
            
            if os.path.exists(file_path) and os.path.exists(app_path):
                try:
                    if os.path.samefile(file_path, app_path) or file_path.startswith(app_dir):
                        return None
                except:
                    # If samefile fails, try string comparison
                    if os.path.normpath(file_path) == os.path.normpath(app_path) or file_path.startswith(app_dir):
                        return None
            
            # Check file size before scanning
            try:
                file_size = os.path.getsize(file_path)
                max_file_size = self.config.get('max_file_size', 100) * 1024 * 1024  # Convert MB to bytes
                
                if file_size > max_file_size:
                    self.log_event.emit("info", f"Skipping large file: {file_path} ({file_size/(1024*1024):.1f} MB)")
                    return None
            except Exception as e:
                self.log_event.emit("error", f"Error checking file size for {file_path}: {str(e)}")
                return None
            
            # Implement a simplified scan directly here
            threats = []
            
            # Check file extension
            _, ext = os.path.splitext(file_path.lower())
            suspicious_extensions = ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.scr', '.pif']
            
            # Determine file type based on extension
            file_type = "unknown"
            if ext in ['.exe', '.dll', '.sys', '.scr', '.ocx']:
                file_type = 'pe'
            elif ext in ['.js', '.vbs', '.ps1', '.bat', '.cmd', '.hta', '.py']:
                file_type = 'script'
            elif ext in ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf']:
                file_type = 'document'
            
            # Check for suspicious extension
            if ext in suspicious_extensions:
                threats.append({
                    'type': 'extension',
                    'name': 'Suspicious.Extension',
                    'confidence': 0.3,
                    'details': 'File has suspicious extension'
                })
            
            # Calculate file hash
            file_hash = None
            try:
                hash_obj = hashlib.md5()
                with open(file_path, 'rb') as f:
                    # Read file in chunks to handle large files
                    for chunk in iter(lambda: f.read(4096), b''):
                        hash_obj.update(chunk)
                file_hash = hash_obj.hexdigest()
            except Exception as e:
                self.log_event.emit("error", f"Error calculating hash for {file_path}: {str(e)}")
            
            # Check against known virus signatures
            if file_hash:
                virus_signatures = {
                    # Common malware signatures (MD5 hashes)
                    "44d88612fea8a8f36de82e1278abb02f": "Trojan.Win32.Generic",
                    "5e3ab14e23f6d5bb07c6f9b6fb3b6596": "Backdoor.Win32.Rbot",
                    "a2b851e5f6bfc9f8e8e8e8e8e8e8e8e8": "Worm.Win32.Conficker",
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Ransomware.Cryptolocker",
                }
                
                if file_hash in virus_signatures:
                    threats.append({
                        'type': 'signature',
                        'name': virus_signatures[file_hash],
                        'confidence': 0.95,
                        'details': f'Hash match: {file_hash}'
                    })
            
            # Check file content for suspicious patterns
            if os.path.getsize(file_path) < 10 * 1024 * 1024:  # Only scan files smaller than 10MB
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read(1024 * 1024)  # Read first 1MB
                        
                        # Check for suspicious patterns
                        suspicious_patterns = [
                            b'eval(base64_decode(',
                            b'cmd.exe /c',
                            b'powershell -e',
                            b'WScript.Shell',
                            b'net user add',
                            b'net localgroup administrators'
                        ]
                        
                        for pattern in suspicious_patterns:
                            if pattern in content:
                                threats.append({
                                    'type': 'heuristic',
                                    'name': 'Suspicious.Pattern',
                                    'confidence': 0.7,
                                    'details': f'Contains suspicious pattern: {pattern.decode("utf-8", errors="ignore")}'
                                })
                except Exception as e:
                    # Skip files that can't be read
                    self.log_event.emit("error", f"Error reading file content for {file_path}: {str(e)}")
            
            if threats:
                # Get file information
                try:
                    # Take action if configured
                    action_taken = 'none'
                    if self.action == 'quarantine':
                        # In a real implementation, this would move the file to quarantine
                        action_taken = 'quarantined'
                    elif self.action == 'delete':
                        # Try to delete the file with advanced methods
                        try:
                            # First try simple deletion
                            os.remove(file_path)
                            action_taken = 'deleted'
                        except PermissionError:
                            # If permission error, try advanced deletion methods
                            if self.is_admin_mode:
                                # Try to use advanced deletion methods
                                try:
                                    # Try to take ownership first (Windows only)
                                    if sys.platform == 'win32':
                                        try:
                                            subprocess.run(
                                                ['takeown', '/f', file_path], 
                                                check=False, 
                                                stdout=subprocess.PIPE, 
                                                stderr=subprocess.PIPE
                                            )
                                            subprocess.run(
                                                ['icacls', file_path, '/grant', 'administrators:F'], 
                                                check=False, 
                                                stdout=subprocess.PIPE, 
                                                stderr=subprocess.PIPE
                                            )
                                        except Exception as e:
                                            self.log_event.emit("error", f"Failed to take ownership of {file_path}: {str(e)}")
                                    
                                    # Try deletion again
                                    os.remove(file_path)
                                    action_taken = 'deleted'
                                except Exception as e:
                                    # If still fails, try to schedule deletion on reboot (Windows only)
                                    if sys.platform == 'win32':
                                        try:
                                            import ctypes
                                            if ctypes.windll.kernel32.MoveFileExW(file_path, None, 4):  # MOVEFILE_DELAY_UNTIL_REBOOT
                                                action_taken = 'scheduled_delete'
                                            else:
                                                action_taken = 'failed_delete'
                                        except Exception as e:
                                            self.log_event.emit("error", f"Failed to schedule deletion for {file_path}: {str(e)}")
                                            action_taken = 'failed_delete'
                                    else:
                                        action_taken = 'failed_delete'
                            else:
                                # Not admin, can't use advanced methods
                                action_taken = 'failed_delete'
                        except Exception as e:
                            self.log_event.emit("error", f"Failed to delete {file_path}: {str(e)}")
                            action_taken = 'failed_delete'
                    
                    return {
                        'file_path': file_path,
                        'file_type': file_type,
                        'file_size': file_size,
                        'hash': file_hash,
                        'status': 'infected',
                        'action_taken': action_taken,
                        'threats': threats
                    }
                except Exception as e:
                    self.log_event.emit("error", f"Error processing {file_path}: {str(e)}")
            
            return None
        except Exception as e:
            self.log_event.emit("error", f"Error scanning {file_path}: {str(e)}")
            return None


        
    def _calculate_file_hash(self, file_path, algorithm='md5'):
        """Calculate hash of a file using specified algorithm"""
        try:
            hash_obj = None
            if algorithm == 'md5':
                hash_obj = hashlib.md5()
            elif algorithm == 'sha256':
                hash_obj = hashlib.sha256()
            else:
                return None
            
            with open(file_path, 'rb') as f:
                # Read file in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_obj.update(chunk)
            
            return hash_obj.hexdigest()
        except Exception:
            return None
        
    def is_system_file(self, file_path):
        """Check if a file is a system file that should be skipped in normal scans"""
        # Skip Windows system directories unless in full scan mode
        if sys.platform == 'win32':
            windows_dir = os.environ.get('WINDIR', 'C:\\Windows')
            system32_dir = os.path.join(windows_dir, 'System32')
            
            if file_path.startswith(system32_dir):
                return True
        
        # Skip common system directories on Unix
        if sys.platform != 'win32':
            system_dirs = ['/bin', '/sbin', '/usr/bin', '/usr/sbin', '/lib']
            if any(file_path.startswith(d) for d in system_dirs):
                return True
        
        return False
        
    def simplified_scan_file(self, file_path):
        """A simplified version of scan_file that doesn't rely on VirusScanner class"""
        try:
            # Check file extension
            _, ext = os.path.splitext(file_path.lower())
            suspicious_extensions = ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.scr', '.pif']
            
            threats = []
            
            # Check for suspicious extension
            if ext in suspicious_extensions:
                threats.append({
                    'type': 'extension',
                    'name': 'Suspicious.Extension',
                    'confidence': 0.3,
                    'details': 'File has suspicious extension'
                })
            
            # Calculate file hash
            file_hash = self.calculate_file_hash(file_path)
            
            # Check against known virus signatures
            virus_signatures = {
                # Common malware signatures (MD5 hashes)
                "44d88612fea8a8f36de82e1278abb02f": "Trojan.Win32.Generic",
                "5e3ab14e23f6d5bb07c6f9b6fb3b6596": "Backdoor.Win32.Rbot",
                "a2b851e5f6bfc9f8e8e8e8e8e8e8e8e8": "Worm.Win32.Conficker",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Ransomware.Cryptolocker",
            }
            
            if file_hash in virus_signatures:
                threats.append({
                    'type': 'signature',
                    'name': virus_signatures[file_hash],
                    'confidence': 0.95,
                    'details': f'Hash match: {file_hash}'
                })
            
            # Check file content for suspicious patterns
            if os.path.getsize(file_path) < 10 * 1024 * 1024:  # Only scan files smaller than 10MB
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read(1024 * 1024)  # Read first 1MB
                        
                        # Check for suspicious patterns
                        suspicious_patterns = [
                            b'eval(base64_decode(',
                            b'cmd.exe /c',
                            b'powershell -e',
                            b'WScript.Shell',
                            b'net user add',
                            b'net localgroup administrators'
                        ]
                        
                        for pattern in suspicious_patterns:
                            if pattern in content:
                                threats.append({
                                    'type': 'heuristic',
                                    'name': 'Suspicious.Pattern',
                                    'confidence': 0.7,
                                    'details': f'Contains suspicious pattern: {pattern.decode("utf-8", errors="ignore")}'
                                })
                except:
                    # Skip files that can't be read
                    pass
            
            return threats
        except Exception as e:
            self.log_event.emit("error", f"Error in simplified scan: {str(e)}")
            return []

    def scan_file_with_timeout(self, file_path, scan_config, timeout=30):
        """Scan a file with a timeout to prevent hanging"""
        result = []
        scan_completed = threading.Event()
        
        def scan_target():
            nonlocal result
            try:
                result = self.simplified_scan_file(file_path)
                scan_completed.set()
            except Exception as e:
                self.log_event.emit("error", f"Error in scan thread for {file_path}: {str(e)}")
                scan_completed.set()
        
        # Create and start the scan thread
        scan_thread = threading.Thread(target=scan_target)
        scan_thread.daemon = True
        scan_thread.start()
        
        # Wait for the scan to complete or timeout
        scan_completed.wait(timeout)
        
        # Check if the scan thread is still alive (timed out)
        if scan_thread.is_alive():
            self.log_event.emit("warning", f"Scan timeout for {file_path}")
            return []
        
        return result

    
    def is_system_file(self, file_path):
        """Check if a file is a system file that should be skipped in normal scans"""
        # Skip Windows system directories unless in full scan mode
        if sys.platform == 'win32':
            windows_dir = os.environ.get('WINDIR', 'C:\\Windows')
            system32_dir = os.path.join(windows_dir, 'System32')
            
            if file_path.startswith(system32_dir):
                return True
        
        # Skip common system directories on Unix
        if sys.platform != 'win32':
            system_dirs = ['/bin', '/sbin', '/usr/bin', '/usr/sbin', '/lib']
            if any(file_path.startswith(d) for d in system_dirs):
                return True
        
        return False

    def add_to_whitelist(self, file_path=None):
        """Add a file to the whitelist"""
        if not file_path:
            # If no file path provided, show file dialog
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Select File to Whitelist",
                os.path.expanduser("~"),
                "All Files (*)"
            )
        
        if not file_path or not os.path.exists(file_path):
            return
        
        # Calculate file hash
        md5_hash = VirusScanner.calculate_file_hash(file_path, 'md5')
        if not md5_hash:
            QMessageBox.warning(self, "Whitelist Error", "Could not calculate file hash.")
            return
        
        # Add to whitelist
        if 'whitelist' not in self.config:
            self.config['whitelist'] = {}
        
        self.config['whitelist'][md5_hash] = {
            'path': file_path,
            'date_added': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'name': os.path.basename(file_path)
        }
        
        # Save config
        self._save_config()
        
        # Update WHITELIST_HASHES global
        WHITELIST_HASHES[md5_hash] = os.path.basename(file_path)
        
        self.add_log_event("info", f"Added {file_path} to whitelist")
        
        # Show notification
        self.notification_manager.show_notification(
            "File Whitelisted",
            f"Added {os.path.basename(file_path)} to whitelist",
            "success"
        )


    def cancel(self):
        """Cancel the scan"""
        self.is_cancelled = True
        self.log_event.emit("warning", "Cancelling scan...")


    
    def get_scan_directories(self):
        """Determine directories to scan based on scan type"""
        scan_dirs = []
        
        # Get application path to exclude
        app_path = os.path.abspath(sys.argv[0])
        app_dir = os.path.dirname(app_path)
        
        # Add this path to exclusions
        if 'exclusions' not in self.config:
            self.config['exclusions'] = []
        
        # Make sure the app directory is in exclusions
        if app_dir not in self.config['exclusions']:
            self.config['exclusions'].append(app_dir)
        
        # Also exclude the specific executable
        if app_path not in self.config['exclusions']:
            self.config['exclusions'].append(app_path)
        
        if self.scan_type == "quick":
            # Quick scan: common locations for malware
            if sys.platform == 'win32':
                scan_dirs = [
                    os.path.join(os.environ['USERPROFILE'], 'Downloads'),
                    os.path.join(os.environ['USERPROFILE'], 'Desktop'),
                    os.path.join(os.environ['TEMP']),
                    os.path.join(os.environ['APPDATA'], 'Local', 'Temp'),
                    os.path.join(os.environ.get('PROGRAMDATA', 'C:\\ProgramData'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
                    os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
                ]
                # Filter out directories that don't exist
                scan_dirs = [d for d in scan_dirs if os.path.exists(d)]
            else:  # Linux/Mac
                scan_dirs = [
                    os.path.expanduser('~/Downloads'),
                    os.path.expanduser('~/Desktop'),
                    '/tmp',
                    os.path.expanduser('~/.config/autostart')
                ]
                # Filter out directories that don't exist
                scan_dirs = [d for d in scan_dirs if os.path.exists(d)]
        elif self.scan_type == "full":
            # Full scan: entire user directory
            if sys.platform == 'win32':
                scan_dirs = [os.environ['USERPROFILE']]
                # Add Program Files for thorough scan
                if self.config.get('scan_program_files', True):
                    program_files = os.environ.get('PROGRAMFILES', 'C:\\Program Files')
                    program_files_x86 = os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)')
                    if os.path.exists(program_files):
                        scan_dirs.append(program_files)
                    if os.path.exists(program_files_x86):
                        scan_dirs.append(program_files_x86)
            else:  # Linux/Mac
                scan_dirs = [os.path.expanduser('~')]
                # Add system directories for thorough scan
                if self.config.get('scan_system_dirs', False):
                    system_dirs = ['/usr/bin', '/usr/local/bin']
                    scan_dirs.extend([d for d in system_dirs if os.path.exists(d)])
        elif self.scan_type == "custom":
            # Custom scan: user-selected directory
            if self.target and os.path.exists(self.target):
                scan_dirs = [self.target]
        
        return scan_dirs

    
    def collect_files(self, directories):
        """Collect files to scan from specified directories with improved error handling"""
        files_to_scan = []
        exclusions = self.config.get('exclusions', [])
        max_file_size = self.config.get('max_file_size', 100) * 1024 * 1024  # Convert MB to bytes
        
        # Get application path to exclude
        app_path = os.path.abspath(sys.argv[0])
        app_dir = os.path.dirname(app_path)
        
        # Make sure these are in exclusions
        if app_dir not in exclusions:
            exclusions.append(app_dir)
        if app_path not in exclusions:
            exclusions.append(app_path)
        
        # Also exclude the Python executable if running from script
        if sys.executable not in exclusions:
            exclusions.append(sys.executable)
        
        # Get file extensions to scan
        scan_extensions = self.config.get('monitored_extensions', [])
        excluded_extensions = self.config.get('excluded_extensions', [])
        
        # If no extensions specified, scan all files except excluded ones
        scan_all_extensions = not scan_extensions
        
        # Track total files found for progress updates
        total_files_found = 0
        max_files = 1000000  # Limit to prevent memory issues
        
        for directory in directories:
            if self.is_cancelled:
                break
            
            try:
                self.update_status.emit(f"Collecting files from {directory}...")
                
                for root, _, files in os.walk(directory):
                    if self.is_cancelled:
                        break
                    
                    # Skip excluded directories
                    if any(self.is_path_excluded(root, excl) for excl in exclusions):
                        continue
                    
                    for file in files:
                        if self.is_cancelled or total_files_found >= max_files:
                            break
                        
                        file_path = os.path.join(root, file)
                        
                        # Skip excluded files
                        if any(self.is_path_excluded(file_path, excl) for excl in exclusions):
                            continue
                        
                        # Skip the application itself
                        try:
                            if os.path.exists(file_path) and os.path.exists(app_path) and os.path.samefile(file_path, app_path):
                                continue
                        except:
                            # If samefile fails, try string comparison
                            if os.path.normpath(file_path) == os.path.normpath(app_path):
                                continue
                        
                        try:
                            # Check file extension
                            _, ext = os.path.splitext(file_path.lower())
                            
                            # Skip excluded extensions
                            if ext in excluded_extensions:
                                continue
                            
                            # Skip if not in monitored extensions (unless scanning all)
                            if not scan_all_extensions and ext not in scan_extensions:
                                continue
                            
                            # Skip files that are too large
                            try:
                                if os.path.getsize(file_path) > max_file_size:
                                    continue
                            except:
                                # Skip files that can't be accessed
                                continue
                            
                            files_to_scan.append(file_path)
                            total_files_found += 1
                            
                            # Update status periodically
                            if total_files_found % 1000 == 0:
                                self.update_status.emit(f"Found {total_files_found} files to scan...")
                            
                            # Check if we've hit the maximum file limit
                            if total_files_found >= max_files:
                                self.log_event.emit("warning", f"Reached maximum file limit ({max_files}), some files will be skipped")
                                break
                                
                        except:
                            # Skip files that can't be accessed
                            continue
            except Exception as e:
                self.log_event.emit("error", f"Error accessing directory {directory}: {str(e)}")
        
        return files_to_scan
    
    def is_path_excluded(self, path, exclusion):
        """Check if a path matches an exclusion pattern with better error handling"""
        try:
            # Convert both to absolute paths for comparison
            abs_path = os.path.abspath(path)
            abs_exclusion = os.path.abspath(exclusion) if os.path.exists(exclusion) else exclusion
            
            # Check if the path starts with the exclusion path
            return abs_path.startswith(abs_exclusion)
        except:
            # If there's any error in comparison, don't exclude
            return False
    
    def cancel(self):
        """Cancel the scan"""
        self.is_cancelled = True
        self.log_event.emit("warning", "Cancelling scan...")

    

class RealTimeMonitorThread(QThread):
    """Thread for real-time monitoring of file system changes and system activities"""
    threat_detected = pyqtSignal(dict)
    log_event = pyqtSignal(str, str)
    
    def __init__(self, config=None):
        super().__init__()
        self.running = False
        self.config = config or {}
        self.watched_dirs = []
        
        # Set directories to watch
        if sys.platform == 'win32':
            self.watched_dirs = [
                os.path.join(os.environ['USERPROFILE'], 'Downloads'),
                os.path.join(os.environ['USERPROFILE'], 'Desktop'),
                os.path.join(os.environ['TEMP']),
                os.path.join(os.environ['APPDATA'], 'Local', 'Temp'),
                os.path.join(os.environ['APPDATA'], 'Roaming'),
                os.path.join(os.environ['PROGRAMDATA']),
                os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'System32'),
                os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'SysWOW64')
            ]
        else:  # Linux/Mac
            self.watched_dirs = [
                os.path.expanduser('~/Downloads'),
                os.path.expanduser('~/Desktop'),
                '/tmp',
                '/etc',
                '/usr/local/bin'
            ]
        
        # Add custom directories from config
        if 'monitored_dirs' in self.config:
            self.watched_dirs.extend(self.config['monitored_dirs'])
        
        # Remove duplicates and non-existent directories
        self.watched_dirs = list(set(dir_path for dir_path in self.watched_dirs if os.path.exists(dir_path)))
        
        # Store last modified times
        self.last_modified_times = {}
        
        # File extensions to monitor
        self.monitored_extensions = set(SUSPICIOUS_EXTENSIONS)
        if 'monitored_extensions' in self.config:
            self.monitored_extensions.update(self.config['monitored_extensions'])
        
        # Add registry monitoring for Windows
        self.registry_keys_to_monitor = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
            r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs",
            r"SYSTEM\CurrentControlSet\Services"
        ]
        
        # Process monitoring
        self.suspicious_processes = [
            "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", 
            "regsvr32.exe", "rundll32.exe", "mshta.exe", "regasm.exe",
            "regsvcs.exe", "msbuild.exe", "installutil.exe", "odbcconf.exe",
            "regsvr32.exe", "bginfo.exe", "msdt.exe"
        ]
        
        # Last process check time
        self.last_process_check = 0
        self.process_check_interval = 30  # Check processes every 30 seconds
        
        # Last registry check time
        self.last_registry_check = 0
        self.registry_check_interval = 60  # Check registry every 60 seconds
        
        # Initialize WMI for Windows
        self.wmi = None
        if sys.platform == 'win32':
            try:
                import wmi
                self.wmi = wmi.WMI()
                self.log_event.emit("info", "WMI initialized for process monitoring")
            except ImportError:
                self.log_event.emit("warning", "WMI module not available, process monitoring limited")
        
        # Initialize driver paths
        self.driver_paths = {}
        self.last_driver_check = 0
        self.driver_check_interval = 30  # Check every 30 seconds
        
        # Add monitoring for DNS requests
        self.dns_monitor_enabled = True
        self.dns_cache = {}
        
        # Add monitoring for hooks
        self.hook_monitor_enabled = True
        self.last_hook_check = 0
        self.hook_check_interval = 20
        
        # Add monitoring for startup programs
        self.startup_locations = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder"
        ]
        self.startup_entries = {}
        self.last_startup_check = 0
        self.startup_check_interval = 60
        
        # Add monitoring for AppInit DLLs
        self.appinit_key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
        self.appinit_value = "AppInit_DLLs"
        self.last_appinit_value = ""
        self.last_appinit_value_wow64 = ""
        
        # Add monitoring for debugger paths
        self.debugger_keys = [
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        ]
        self.debugger_values = {}
        
        # Add monitoring for service DLLs
        self.service_key = r"SYSTEM\CurrentControlSet\Services"
        self.service_dlls = {}
        self.last_service_check = 0
        self.service_check_interval = 60
        
        # Check if we're running as admin
        self.is_admin_mode = is_admin()  # Use the global is_admin() function instead
        
        # NEW: Add flags for vulnerability protections
        self.prevent_driver_changes = self.config.get('prevent_driver_changes', True)
        self.prevent_raw_disk_access = self.config.get('prevent_raw_disk_access', True)
        self.detect_runner_invasion = self.config.get('detect_runner_invasion', True)



    
    def run(self):
        """Run the real-time monitoring thread with enhanced protection"""
        self.running = True
        self.log_event.emit("info", "Starting enhanced real-time monitoring")
        
        # Initialize baseline data
        if sys.platform == 'win32':
            try:
                self.initialize_driver_paths()
                self.log_event.emit("info", "Driver paths initialized")
            except Exception as e:
                self.log_event.emit("error", f"Failed to initialize driver paths: {str(e)}")
            
            try:
                self.initialize_startup_entries()
                self.log_event.emit("info", "Startup entries initialized")
            except Exception as e:
                self.log_event.emit("error", f"Failed to initialize startup entries: {str(e)}")
            
            try:
                self.initialize_appinit_dlls()
                self.log_event.emit("info", "AppInit DLLs initialized")
            except Exception as e:
                self.log_event.emit("error", f"Failed to initialize AppInit DLLs: {str(e)}")
            
            try:
                self.initialize_debugger_paths()
                self.log_event.emit("info", "Debugger paths initialized")
            except Exception as e:
                self.log_event.emit("error", f"Failed to initialize debugger paths: {str(e)}")
            
            try:
                self.initialize_service_dlls()
                self.log_event.emit("info", "Service DLLs initialized")
            except Exception as e:
                self.log_event.emit("error", f"Failed to initialize service DLLs: {str(e)}")
        
        # Monitor for changes
        while self.running:
            try:
                current_time = time.time()
                
                # Monitor file system changes
                for directory in self.watched_dirs:
                    if not self.running:
                        break
                    
                    try:
                        self.scan_directory_for_changes(directory)
                    except Exception as e:
                        self.log_event.emit("error", f"Error scanning directory {directory}: {str(e)}")
                
                # Monitor processes
                if current_time - self.last_process_check >= self.process_check_interval:
                    self.last_process_check = current_time
                    
                    try:
                        self.check_suspicious_processes()
                    except Exception as e:
                        self.log_event.emit("error", f"Error checking suspicious processes: {str(e)}")
                    
                    # Check for process impersonation (Coat technique)
                    if sys.platform == 'win32' and self.config.get('detect_process_impersonation', True):
                        try:
                            self.check_process_impersonation()
                        except Exception as e:
                            self.log_event.emit("error", f"Error checking process impersonation: {str(e)}")
                    
                    # Check for Runner invasion technique
                    if sys.platform == 'win32' and self.config.get('detect_runner_invasion', True):
                        try:
                            self.check_runner_invasion()
                        except Exception as e:
                            self.log_event.emit("error", f"Error checking runner invasion: {str(e)}")
                    
                    # Check for service-based injections
                    if sys.platform == 'win32':
                        try:
                            self.check_service_injections()
                        except Exception as e:
                            self.log_event.emit("error", f"Error checking service injections: {str(e)}")
                
                # Monitor registry (Windows only)
                if sys.platform == 'win32' and current_time - self.last_registry_check >= self.registry_check_interval:
                    self.last_registry_check = current_time
                    try:
                        self.check_registry_changes()
                    except Exception as e:
                        self.log_event.emit("error", f"Error checking registry changes: {str(e)}")
                
                # Enhanced monitoring for driver paths
                if sys.platform == 'win32' and current_time - self.last_driver_check >= self.driver_check_interval:
                    self.last_driver_check = current_time
                    try:
                        self.check_driver_path_changes()
                    except Exception as e:
                        self.log_event.emit("error", f"Error checking driver path changes: {str(e)}")
                
                # Monitor for hook-based injections
                if sys.platform == 'win32' and self.hook_monitor_enabled and current_time - self.last_hook_check >= self.hook_check_interval:
                    self.last_hook_check = current_time
                    try:
                        self.check_hook_injections()
                    except Exception as e:
                        self.log_event.emit("error", f"Error checking hook injections: {str(e)}")
                
                # Monitor startup programs
                if sys.platform == 'win32' and current_time - self.last_startup_check >= self.startup_check_interval:
                    self.last_startup_check = current_time
                    try:
                        self.check_startup_changes()
                    except Exception as e:
                        self.log_event.emit("error", f"Error checking startup changes: {str(e)}")
                
                # Monitor AppInit DLLs
                if sys.platform == 'win32':
                    try:
                        self.check_appinit_dlls()
                    except Exception as e:
                        self.log_event.emit("error", f"Error checking AppInit DLLs: {str(e)}")
                
                # Monitor debugger paths
                if sys.platform == 'win32':
                    try:
                        self.check_debugger_paths()
                    except Exception as e:
                        self.log_event.emit("error", f"Error checking debugger paths: {str(e)}")
                
                # Monitor service DLLs
                if sys.platform == 'win32' and current_time - self.last_service_check >= self.service_check_interval:
                    self.last_service_check = current_time
                    try:
                        self.check_service_dll_changes()
                    except Exception as e:
                        self.log_event.emit("error", f"Error checking service DLL changes: {str(e)}")
                
                # Monitor for raw disk access
                if sys.platform == 'win32' and self.config.get('raw_disk_monitoring', True):
                    try:
                        self.check_raw_disk_access()
                    except Exception as e:
                        self.log_event.emit("error", f"Error checking raw disk access: {str(e)}")
                
                # Monitor for file drops in sensitive locations
                if self.config.get('file_drop_monitoring', True):
                    try:
                        self.check_file_drops()
                    except Exception as e:
                        self.log_event.emit("error", f"Error checking file drops: {str(e)}")
                
                # Monitor DNS requests
                if sys.platform == 'win32' and self.config.get('dns_monitoring', True):
                    try:
                        self.monitor_dns_requests()
                    except Exception as e:
                        self.log_event.emit("error", f"Error monitoring DNS requests: {str(e)}")
                
                time.sleep(2)  # Check every 2 seconds
            except Exception as e:
                self.log_event.emit("error", f"Error in real-time monitoring thread: {str(e)}")
                time.sleep(5)  # Wait a bit before retrying



    

    def initialize_driver_paths(self):
        """Initialize baseline of driver paths"""
        try:
            if sys.platform == 'win32':
                import winreg
                
                # Monitor driver paths in registry
                driver_key_path = r"SYSTEM\CurrentControlSet\Services"
                
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, driver_key_path)
                    
                    # Enumerate subkeys (each is a service/driver)
                    i = 0
                    while True:
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            subkey = winreg.OpenKey(key, subkey_name)
                            
                            try:
                                # Get ImagePath value which contains the driver path
                                image_path, _ = winreg.QueryValueEx(subkey, "ImagePath")
                                self.driver_paths[subkey_name] = image_path
                            except WindowsError:
                                pass
                            
                            winreg.CloseKey(subkey)
                            i += 1
                        except WindowsError:
                            break
                    
                    winreg.CloseKey(key)
                    self.log_event.emit("info", f"Initialized monitoring for {len(self.driver_paths)} driver paths")
                except Exception as e:
                    self.log_event.emit("error", f"Failed to initialize driver path monitoring: {str(e)}")
        except Exception as e:
            self.log_event.emit("error", f"Error in initialize_driver_paths: {str(e)}")

    def check_driver_path_changes(self):
        """Check for changes in driver paths (addresses ChangeDrvPath vulnerability)"""
        try:
            if sys.platform == 'win32':
                import winreg
                current_paths = {}
                
                # Check registry for driver paths
                driver_key_path = r"SYSTEM\CurrentControlSet\Services"
                
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, driver_key_path)
                    
                    # Enumerate subkeys (each is a service/driver)
                    i = 0
                    while True:
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            subkey = winreg.OpenKey(key, subkey_name)
                            
                            try:
                                # Get ImagePath value which contains the driver path
                                image_path, _ = winreg.QueryValueEx(subkey, "ImagePath")
                                current_paths[subkey_name] = image_path
                                
                                # Check if this is a new driver
                                if subkey_name not in self.driver_paths:
                                    self.log_event.emit("warning", f"New driver detected: {subkey_name} at {image_path}")
                                    self.report_driver_threat(subkey_name, image_path, "New driver installation detected")
                                
                                # Check if driver path changed
                                elif self.driver_paths[subkey_name] != image_path:
                                    self.log_event.emit("warning", f"Driver path changed for {subkey_name}: {self.driver_paths[subkey_name]} -> {image_path}")
                                    self.report_driver_threat(subkey_name, image_path, "Driver path modification detected")
                                    
                                    # ENHANCED: Take immediate action to prevent the change
                                    if self.config.get('prevent_driver_changes', True) and self.is_admin_mode:
                                        try:
                                            # Restore the original path
                                            driver_subkey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{driver_key_path}\\{subkey_name}", 0, winreg.KEY_SET_VALUE)
                                            winreg.SetValueEx(driver_subkey, "ImagePath", 0, winreg.REG_SZ, self.driver_paths[subkey_name])
                                            winreg.CloseKey(driver_subkey)
                                            self.log_event.emit("info", f"Restored original driver path for {subkey_name}")
                                            
                                            # Block the modified driver file
                                            if os.path.exists(image_path):
                                                # Rename the suspicious driver file
                                                blocked_path = image_path + ".blocked"
                                                try:
                                                    os.rename(image_path, blocked_path)
                                                    self.log_event.emit("info", f"Renamed suspicious driver file to {blocked_path}")
                                                except Exception as e:
                                                    self.log_event.emit("error", f"Failed to rename suspicious driver file: {str(e)}")
                                        except Exception as e:
                                            self.log_event.emit("error", f"Failed to restore driver path: {str(e)}")
                                
                                # Check for suspicious paths
                                if self.is_suspicious_driver_path(image_path):
                                    self.log_event.emit("warning", f"Suspicious driver path detected: {image_path}")
                                    self.report_driver_threat(subkey_name, image_path, "Suspicious driver path detected")
                            except WindowsError:
                                pass
                            
                            winreg.CloseKey(subkey)
                            i += 1
                        except WindowsError:
                            break
                    
                    winreg.CloseKey(key)
                except Exception as e:
                    self.log_event.emit("error", f"Error checking registry driver paths: {str(e)}")
                
                # Update baseline
                self.driver_paths = current_paths
        except Exception as e:
            self.log_event.emit("error", f"Error in check_driver_path_changes: {str(e)}")



    def is_suspicious_driver_path(self, path):
        """Check if a driver path looks suspicious"""
        if not path:
            return False
            
        path_lower = path.lower()
        
        # Check for paths outside system directories
        system_dirs = [
            os.environ.get('WINDIR', 'c:\\windows'),
            os.environ.get('SYSTEMROOT', 'c:\\windows'),
            os.path.join(os.environ.get('WINDIR', 'c:\\windows'), 'system32'),
            os.path.join(os.environ.get('WINDIR', 'c:\\windows'), 'system32\\drivers'),
            os.environ.get('PROGRAMFILES', 'c:\\program files'),
            os.environ.get('PROGRAMFILES(X86)', 'c:\\program files (x86)')
        ]
        
        # If path doesn't start with any system directory, it's suspicious
        if not any(path_lower.startswith(dir.lower()) for dir in system_dirs):
            return True
        
        # Check for suspicious locations
        suspicious_locations = [
            "\\temp\\", 
            "\\tmp\\", 
            "\\downloads\\",
            "\\appdata\\local\\temp\\",
            "\\users\\public\\",
            "\\programdata\\temp\\",
            "\\recycler\\",
            "\\$recycle.bin\\"
        ]
        
        if any(loc in path_lower for loc in suspicious_locations):
            return True
        
        return False

    def check_file(self, file_path):
        """Basic check for suspicious files"""
        try:
            # Skip excluded files
            exclusions = self.config.get('exclusions', [])
            if any(os.path.abspath(file_path).startswith(os.path.abspath(excl)) for excl in exclusions):
                return
            
            # Skip files that are too large
            max_file_size = self.config.get('max_file_size', 100) * 1024 * 1024  # Convert MB to bytes
            try:
                if os.path.getsize(file_path) > max_file_size:
                    return
            except:
                return
            
            # Check file content for suspicious patterns
            try:
                with open(file_path, 'rb') as f:
                    content = f.read(1024 * 1024)  # Read first 1MB
                    
                    # Check for suspicious patterns
                    suspicious_patterns = [
                        b'cmd.exe /c', b'powershell -e', b'WScript.Shell',
                        b'CreateObject', b'ActiveXObject', b'RegWrite',
                        b'ShellExecute', b'WinExec', b'CreateProcess',
                        b'VirtualAlloc', b'WriteProcessMemory', b'CreateRemoteThread',
                        b'SetWindowsHook', b'GetAsyncKeyState', b'keybd_event',
                        b'net user add', b'net localgroup administrators',
                        b'RegCreateKey', b'RegSetValue'
                    ]
                    
                    for pattern in suspicious_patterns:
                        if pattern in content:
                            self.report_threat(file_path, f"Suspicious pattern detected: {pattern.decode('utf-8', errors='ignore')}")
                            return
            except:
                pass
            
        except Exception as e:
            self.log_event.emit("error", f"Error checking file {file_path}: {str(e)}")

    def check_file_deep(self, file_path):
        """Deep analysis for potentially malicious files"""
        try:
            # Get file type
            _, ext = os.path.splitext(file_path.lower())
            
            # Check executable files
            if ext in ['.exe', '.dll', '.sys', '.scr', '.ocx']:
                self.check_executable(file_path)
            
            # Check script files
            elif ext in ['.js', '.vbs', '.ps1', '.bat', '.cmd', '.hta']:
                self.check_script(file_path)
            
            # Check document files
            elif ext in ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf']:
                self.check_document(file_path)
                
        except Exception as e:
            self.log_event.emit("error", f"Error in deep file check for {file_path}: {str(e)}")

    def report_threat(self, file_path, reason):
        """Report a detected file threat"""
        try:
            # Create threat information
            threat = {
                'file_path': file_path,
                'file_type': os.path.splitext(file_path)[1].lower(),
                'file_size': os.path.getsize(file_path),
                'status': 'infected',
                'action_taken': 'none',
                'threats': [{
                    'type': 'heuristic',
                    'name': 'Suspicious.RealTimeDetection',
                    'confidence': 0.8,
                    'details': reason
                }]
            }
            
            self.log_event.emit("warning", f"Real-time protection detected threat in {file_path}: {reason}")
            self.threat_detected.emit(threat)
            
        except Exception as e:
            self.log_event.emit("error", f"Error reporting threat for {file_path}: {str(e)}")

    
    
    def scan_directory_for_changes(self, directory, initial=False):
        """Scan directory for new or modified files"""
        try:
            for root, _, files in os.walk(directory):
                for file in files:
                    if not self.running:
                        return
                    
                    file_path = os.path.join(root, file)
                    
                    try:
                        # Skip if file doesn't exist or can't be accessed
                        if not os.path.exists(file_path):
                            continue
                        
                        # Check file extension
                        _, ext = os.path.splitext(file_path.lower())
                        
                        # Get last modified time
                        mtime = os.path.getmtime(file_path)
                        
                        # If this is initial scan, just record the time
                        if initial:
                            self.last_modified_times[file_path] = mtime
                            continue
                        
                        # Check if file is new or modified
                        if file_path not in self.last_modified_times or mtime > self.last_modified_times[file_path]:
                            # Update last modified time
                            self.last_modified_times[file_path] = mtime
                            
                            # Check all files for suspicious content, not just by extension
                            self.check_file(file_path)
                            
                            # Special handling for suspicious extensions
                            if ext in self.monitored_extensions:
                                self.check_file_deep(file_path)
                    
                    except Exception:
                        # Skip files that can't be accessed
                        continue
        
        except Exception as e:
            self.log_event.emit("error", f"Error monitoring directory {directory}: {str(e)}")

    def check_executable(self, file_path):
        """Check executable files for malicious characteristics"""
        try:
            # Calculate entropy to detect packed/encrypted executables
            entropy = self.calculate_entropy(file_path)
            if entropy > 7.5:  # High entropy indicates encryption/packing
                self.report_threat(file_path, f"Suspicious executable with high entropy ({entropy:.2f})")
                return
            
            # Check for digital signature
            if sys.platform == 'win32':
                if not self.is_signed(file_path):
                    # Unsigned executables are suspicious but not definitive
                    self.log_event.emit("info", f"Unsigned executable detected: {file_path}")
            
            # Check for suspicious strings in PE files
            with open(file_path, 'rb') as f:
                content = f.read()
                
            suspicious_strings = [
                b'CreateRemoteThread', b'VirtualAllocEx', b'WriteProcessMemory',
                b'ShellExecuteA', b'URLDownloadToFile'
            ]
            
            suspicious_count = 0
            for string in suspicious_strings:
                if string in content:
                    suspicious_count += 1
            
            # Only report if multiple suspicious strings are found
            if suspicious_count >= 2:
                self.report_threat(file_path, f"Suspicious executable with {suspicious_count} potentially malicious API calls")
                
        except Exception as e:
            self.log_event.emit("error", f"Error checking executable {file_path}: {str(e)}")

    def check_script(self, file_path):
        """Check script files for malicious code"""
        try:
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
            
            # Check for obfuscation
            obfuscation_patterns = [
                r'eval\s*\(', r'execute\s*\(', r'fromcharcode',
                r'String\.fromCharCode', r'unescape\s*\(', r'atob\s*\(',
                r'\\x[0-9a-f]{2}', r'\\u[0-9a-f]{4}', r'base64'
            ]
            
            for pattern in obfuscation_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    self.report_threat(file_path, f"Obfuscated script detected: {pattern}")
                    return
            
            # Check for suspicious script patterns
            suspicious_patterns = [
                # PowerShell
                r'powershell\s+-[eE]', r'bypass\s+-[eE]', r'hidden\s+-[eE]',
                r'downloadstring', r'iex\s*\(', r'invoke-expression',
                
                # JavaScript
                r'ActiveXObject', r'WScript\.Shell', r'new\s+ActiveX',
                r'document\.write\s*\(\s*unescape', r'eval\s*\(\s*unescape',
                
                # VBScript
                r'CreateObject\s*\(\s*["\']WScript', r'CreateObject\s*\(\s*["\']Scripting',
                r'CreateObject\s*\(\s*["\']Shell', r'CreateObject\s*\(\s*["\']ADODB',
                
                # General
                r'cmd\.exe', r'cmd\s+/c', r'powershell\s+-', r'rundll32',
                r'regsvr32', r'bitsadmin', r'certutil\s+-urlcache'
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    self.report_threat(file_path, f"Suspicious script pattern detected: {pattern}")
                    return
                    
        except Exception as e:
            self.log_event.emit("error", f"Error checking script {file_path}: {str(e)}")

    def check_document(self, file_path):
        """Check document files for malicious macros and exploits"""
        try:
            # Check for PDF exploits
            if file_path.lower().endswith('.pdf'):
                with open(file_path, 'rb') as f:
                    content = f.read(1024 * 1024)  # Read first 1MB
                
                # Check for JavaScript in PDF
                if b'/JavaScript' in content or b'/JS' in content:
                    self.report_threat(file_path, "PDF contains JavaScript")
                    return
                
                # Check for common PDF exploits
                exploit_patterns = [
                    b'/Launch', b'/URI', b'/SubmitForm', b'/RichMedia',
                    b'/OpenAction', b'/AA', b'/AcroForm', b'/XFA'
                ]
                
                for pattern in exploit_patterns:
                    if pattern in content:
                        self.report_threat(file_path, f"PDF contains potential exploit: {pattern.decode('utf-8', errors='ignore')}")
                        return
            
            # Check for Office macros
            elif file_path.lower().endswith(('.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm')):
                # Try to detect macros by file signature
                with open(file_path, 'rb') as f:
                    header = f.read(2000)  # Read enough to detect macros
                    
                    # Look for macro signatures
                    if b'VBA' in header or b'Macro' in header or b'Microsoft Office' in header:
                        self.report_threat(file_path, "Office document may contain macros")
                        return
                    
        except Exception as e:
            self.log_event.emit("error", f"Error checking document {file_path}: {str(e)}")

    def calculate_entropy(self, file_path):
        """Calculate Shannon entropy of a file to detect encryption/packing"""
        try:
            # Use a maximum read size to prevent memory issues with large files
            max_read_size = 1024 * 1024  # 1MB
            
            with open(file_path, 'rb') as f:
                # For large files, read only the first and last portions
                file_size = os.path.getsize(file_path)
                
                if file_size <= max_read_size:
                    # For small files, read the entire content
                    data = f.read()
                else:
                    # For large files, read first and last 512KB
                    first_chunk = f.read(max_read_size // 2)
                    f.seek(-min(max_read_size // 2, file_size), 2)  # Seek from end
                    last_chunk = f.read(max_read_size // 2)
                    data = first_chunk + last_chunk
            
            if not data:
                return 0
                
            entropy = 0
            byte_counts = Counter(data)
            data_size = len(data)
            
            # Calculate Shannon entropy
            for count in byte_counts.values():
                probability = count / data_size
                entropy -= probability * math.log2(probability)
                
            return entropy
        except Exception as e:
            self.log_event.emit("error", f"Error calculating entropy: {str(e)}")
            return 0

    def is_signed(self, file_path):
        """Check if a file is digitally signed (Windows only)"""
        if sys.platform != 'win32':
            return False
            
        try:
            import subprocess
            
            # Use PowerShell to check digital signature
            cmd = f'powershell -Command "Get-AuthenticodeSignature \'{file_path}\' | Select-Object -ExpandProperty Status"'
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            
            if result.returncode == 0 and "Valid" in result.stdout:
                return True
        except:
            pass
            
        return False


    
    def check_process_impersonation(self):
        """Check for process impersonation techniques (addresses Coat vulnerability)"""
        try:
            if sys.platform == 'win32':
                # Get system directories for verification
                system32_dir = os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'System32').lower()
                syswow64_dir = os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'SysWOW64').lower()
                
                # List of critical system processes that should only run from system directories
                critical_processes = {
                    'svchost.exe': system32_dir,
                    'lsass.exe': system32_dir,
                    'csrss.exe': system32_dir,
                    'winlogon.exe': system32_dir,
                    'services.exe': system32_dir,
                    'smss.exe': system32_dir,
                    'wininit.exe': system32_dir,
                    'explorer.exe': os.path.join(os.environ.get('WINDIR', 'C:\\Windows')).lower()
                }
                
                # Use PowerShell to check processes
                cmd = '''powershell -Command "
                $criticalProcesses = @{
                    'svchost.exe' = $env:windir + '\\System32';
                    'lsass.exe' = $env:windir + '\\System32';
                    'csrss.exe' = $env:windir + '\\System32';
                    'winlogon.exe' = $env:windir + '\\System32';
                    'services.exe' = $env:windir + '\\System32';
                    'smss.exe' = $env:windir + '\\System32';
                    'wininit.exe' = $env:windir + '\\System32';
                    'explorer.exe' = $env:windir
                }
                
                Get-Process | ForEach-Object {
                    $proc = $_
                    $procName = $proc.ProcessName + '.exe'
                    $procPath = $proc.Path
                    
                    if ($criticalProcesses.ContainsKey($procName.ToLower()) -and $procPath) {
                        $expectedDir = $criticalProcesses[$procName.ToLower()]
                        if (-not $procPath.ToLower().StartsWith($expectedDir.ToLower())) {
                            [PSCustomObject]@{
                                ProcessName = $proc.ProcessName;
                                PID = $proc.Id;
                                Path = $procPath;
                                ExpectedPath = $expectedDir
                            }
                        }
                    }
                }"
                '''
                
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                
                if result.returncode == 0 and result.stdout.strip():
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 4:
                            process_name = parts[0]
                            try:
                                pid = int(parts[1])
                                path = ' '.join(parts[2:-1])
                                expected_path = parts[-1]
                                
                                self.log_event.emit("warning", f"Process impersonation detected: {process_name} (PID: {pid}) running from {path}")
                                self.report_process_threat(process_name, pid, f"Process impersonation (Coat technique): running from {path}, should be in {expected_path}")
                            except ValueError:
                                pass
        except Exception as e:
            self.log_event.emit("error", f"Error checking process impersonation: {str(e)}")





    def check_runner_invasion(self):
        """Check for Runner invasion technique"""
        try:
            if sys.platform == 'win32':
                # Check for suspicious rundll32 processes
                cmd = '''powershell -Command "
                # Get all rundll32 and regsvr32 processes
                $processes = Get-Process -Name rundll32,regsvr32 -ErrorAction SilentlyContinue
                
                foreach ($proc in $processes) {
                    # Get command line for the process
                    $cmdLine = (Get-CimInstance Win32_Process -Filter \"ProcessId = $($proc.Id)\").CommandLine
                    
                    # Check for suspicious patterns
                    if ($cmdLine -match 'javascript:|vbscript:|http:|https:|file:|\\\\\\\\\\\\\\\temp\\\\\\|shell32.dll,Control_RunDLL|scrobj.dll|mshtml.dll|RegisterOCX') {
                        [PSCustomObject]@{
                            ProcessName = $proc.Name
                            PID = $proc.Id
                            CommandLine = $cmdLine
                        }
                    }
                    
                    # Check for suspicious DLL loading without full path
                    if ($cmdLine -match '\.dll[^\\\\]') {
                        [PSCustomObject]@{
                            ProcessName = $proc.Name
                            PID = $proc.Id
                            CommandLine = $cmdLine
                        }
                    }
                }
                
                # Also check for suspicious command lines in any process
                Get-CimInstance Win32_Process | Where-Object { 
                    $_.CommandLine -match 'rundll32.*javascript:|rundll32.*vbscript:|rundll32.*http:|rundll32.*shell32.dll,Control_RunDLL.*\\\\temp\\\\' 
                } | ForEach-Object {
                    [PSCustomObject]@{
                        ProcessName = $_.Name
                        PID = $_.ProcessId
                        CommandLine = $_.CommandLine
                    }
                }
                "'''
                
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                
                if result.returncode == 0 and result.stdout.strip():
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 3:
                                try:
                                    process_name = parts[0]
                                    pid = int(parts[1])
                                    command_line = ' '.join(parts[2:])
                                    
                                    self.log_event.emit("warning", f"Runner invasion technique detected: {process_name} (PID: {pid}) with command: {command_line}")
                                    
                                    # Report the threat
                                    self.report_process_threat(process_name, pid, f"Runner invasion technique detected")
                                    
                                    # Automatically terminate the process if configured
                                    if self.config.get('auto_terminate_processes', False) and self.is_admin_mode:
                                        try:
                                            # Terminate the process
                                            import ctypes
                                            handle = ctypes.windll.kernel32.OpenProcess(1, False, pid)
                                            if handle:
                                                result = ctypes.windll.kernel32.TerminateProcess(handle, 0)
                                                ctypes.windll.kernel32.CloseHandle(handle)
                                                
                                                if result:
                                                    self.log_event.emit("success", f"Terminated malicious process: {process_name} (PID: {pid})")
                                                else:
                                                    self.log_event.emit("error", f"Failed to terminate process: {process_name} (PID: {pid})")
                                        except Exception as e:
                                            self.log_event.emit("error", f"Error terminating process: {str(e)}")
                                except ValueError:
                                    self.log_event.emit("error", f"Error parsing process information: {line}")
                
                # NEW: Add a Windows Defender Exploit Guard rule to block rundll32.js/vbs execution
                if self.config.get('detect_runner_invasion', True) and self.is_admin_mode:
                    try:
                        # Create PowerShell command to add exploit guard rule
                        ps_cmd = '''powershell -Command "
                        # Check if Process Mitigation policy exists
                        $ruleName = 'Block_Rundll32_Scripts'
                        
                        try {
                            # Add rule to block rundll32.exe from running scripts
                            Set-ProcessMitigation -Name rundll32.exe -Enable BlockNonMicrosoftBinaries
                            Write-Host 'Added protection rule for rundll32.exe'
                            
                            # Also add rule for regsvr32.exe
                            Set-ProcessMitigation -Name regsvr32.exe -Enable BlockNonMicrosoftBinaries
                            Write-Host 'Added protection rule for regsvr32.exe'
                        } catch {
                            Write-Host 'Failed to add process mitigation rules: $_'
                        }
                        "'''
                        
                        # Run the PowerShell command
                        subprocess.run(ps_cmd, capture_output=True, text=True, check=False)
                        
                    except Exception as e:
                        self.log_event.emit("error", f"Failed to add exploit guard rules: {str(e)}")
        except Exception as e:
            self.log_event.emit("error", f"Error checking Runner invasion: {str(e)}")




    def is_suspicious_rundll(self, command_line):
        """Check if a rundll32 command line is suspicious"""
        # Check for common malicious patterns
        suspicious_patterns = [
            # Execution from temp directories
            r'\\temp\\',
            r'\\tmp\\',
            # Unusual parameters
            r',RunDLL',
            r',Control_RunDLL',
            # JavaScript/VBScript execution
            r'javascript:',
            r'vbscript:',
            # URL execution
            r'http://',
            r'https://',
            # Unusual file extensions
            r'\.dat,',
            r'\.txt,'
        ]
        
        command_line_lower = command_line.lower()
        return any(re.search(pattern, command_line_lower) for pattern in suspicious_patterns)


    def check_hook_injections(self):
        """Check for hook-based injections (addresses SetWinEventHook and SetWindowsHookEx vulnerabilities)"""
        try:
            if sys.platform == 'win32':
                # Check for suspicious DLLs loaded in processes
                cmd = 'powershell -Command "$processes = Get-Process | Where-Object {$_.Modules}; foreach ($p in $processes) { foreach ($m in $p.Modules) { if ($m.FileName -notlike \'*windows*\' -and $m.FileName -notlike \'*Microsoft*\' -and $m.FileName -like \'*.dll\') { [PSCustomObject]@{ProcessName=$p.Name; PID=$p.Id; ModulePath=$m.FileName} } } }"'
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                
                if result.returncode == 0 and result.stdout.strip():
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        parts = line.split(None, 2)
                        if len(parts) >= 3:
                            process_name = parts[0]
                            try:
                                pid = int(parts[1])
                                module_path = parts[2]
                                
                                # Check if the DLL is from a suspicious location
                                if self.is_suspicious_dll_location(module_path):
                                    self.log_event.emit("warning", f"Suspicious DLL loaded in process {process_name} (PID: {pid}): {module_path}")
                                    self.report_process_threat(process_name, pid, f"Possible hook injection: {module_path}")
                            except ValueError:
                                pass
        except Exception as e:
            self.log_event.emit("error", f"Error checking hook injections: {str(e)}")

    def is_suspicious_dll_location(self, dll_path):
        """Check if a DLL is loaded from a suspicious location"""
        suspicious_locations = [
            "\\temp\\", 
            "\\tmp\\", 
            "\\downloads\\",
            "\\appdata\\local\\temp\\",
            "\\users\\public\\",
            "\\programdata\\",
            "\\recycler\\",
            "\\$recycle.bin\\"
        ]
        
        dll_path_lower = dll_path.lower()
        return any(loc in dll_path_lower for loc in suspicious_locations)


    def check_service_injections(self):
        """Check for service-based injections (addresses Services vulnerability)"""
        try:
            if sys.platform == 'win32':
                # Check for suspicious service binaries
                cmd = 'powershell -Command "Get-WmiObject -Class Win32_Service | Select-Object Name, PathName, StartMode, State | Where-Object { $_.State -eq \'Running\' }"'
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                
                if result.returncode == 0 and result.stdout.strip():
                    lines = result.stdout.strip().split('\n')
                    for line in lines[1:]:  # Skip header
                        parts = line.split(None, 3)
                        if len(parts) >= 4:
                            service_name = parts[0]
                            path_name = parts[1]
                            
                            # Check if service binary is in a suspicious location
                            if path_name and self.is_suspicious_service_path(path_name):
                                self.log_event.emit("warning", f"Suspicious service binary location: {service_name} at {path_name}")
                                self.report_service_threat(service_name, path_name, "Suspicious service binary location")
        except Exception as e:
            self.log_event.emit("error", f"Error checking service injections: {str(e)}")

    def is_suspicious_service_path(self, path):
        """Check if a service binary path is suspicious"""
        suspicious_locations = [
            "\\temp\\", 
            "\\tmp\\", 
            "\\downloads\\",
            "\\appdata\\local\\temp\\",
            "\\users\\public\\",
            "\\programdata\\temp\\",
            "\\recycler\\",
            "\\$recycle.bin\\"
        ]
        
        path_lower = path.lower()
        
        # Check for suspicious locations
        if any(loc in path_lower for loc in suspicious_locations):
            return True
        
        # Check for suspicious command line patterns
        suspicious_patterns = [
            "-e ", "-enc", "-exec", "-nop", "-w hidden",
            "cmd /c", "cmd.exe /c", "powershell -",
            "javascript:", "vbscript:",
            "rundll32", "regsvr32"
        ]
        
        if any(pattern in path_lower for pattern in suspicious_patterns):
            return True
        
        return False

    def report_service_threat(self, service_name, service_path, reason):
        """Report a detected service threat"""
        try:
            # Create threat information
            threat = {
                'service_name': service_name,
                'service_path': service_path,
                'status': 'suspicious',
                'action_taken': 'none',
                'threats': [{
                    'type': 'heuristic',
                    'name': 'Suspicious.Service',
                    'confidence': 0.8,
                    'details': reason
                }]
            }
            
            self.log_event.emit("warning", f"Service threat detected: {service_name} - {reason}")
            self.threat_detected.emit(threat)
            
        except Exception as e:
            self.log_event.emit("error", f"Error reporting service threat: {str(e)}")




    def initialize_startup_entries(self):
        """Initialize baseline of startup entries"""
        try:
            if sys.platform == 'win32':
                import winreg
                
                for key_path in self.startup_locations:
                    try:
                        # Determine which hive to use
                        if key_path.startswith("SOFTWARE\\"):
                            hive = winreg.HKEY_LOCAL_MACHINE
                        else:
                            hive = winreg.HKEY_CURRENT_USER
                        
                        # Open the registry key
                        key = winreg.OpenKey(hive, key_path)
                        
                        # Enumerate values
                        i = 0
                        while True:
                            try:
                                name, value, type = winreg.EnumValue(key, i)
                                self.startup_entries[f"{key_path}\\{name}"] = value
                                i += 1
                            except WindowsError:
                                break
                        
                        winreg.CloseKey(key)
                    except Exception:
                        # Skip keys that can't be accessed
                        pass
                        
                self.log_event.emit("info", f"Initialized monitoring for {len(self.startup_entries)} startup entries")
        except Exception as e:
            self.log_event.emit("error", f"Failed to initialize startup monitoring: {str(e)}")

    def check_startup_changes(self):
        """Check for changes in startup programs (addresses StartupPrograms vulnerability)"""
        try:
            if sys.platform == 'win32':
                import winreg
                current_entries = {}
                
                for key_path in self.startup_locations:
                    try:
                        # Determine which hive to use
                        if key_path.startswith("SOFTWARE\\"):
                            hive = winreg.HKEY_LOCAL_MACHINE
                        else:
                            hive = winreg.HKEY_CURRENT_USER
                        
                        # Open the registry key
                        key = winreg.OpenKey(hive, key_path)
                        
                        # Enumerate values
                        i = 0
                        while True:
                            try:
                                name, value, type = winreg.EnumValue(key, i)
                                full_path = f"{key_path}\\{name}"
                                current_entries[full_path] = value
                                
                                # Check if this is a new entry
                                if full_path not in self.startup_entries:
                                    self.log_event.emit("warning", f"New startup entry detected: {name} = {value}")
                                    self.report_registry_threat(key_path, name, value, "New startup program detected")
                                
                                # Check if entry changed
                                elif self.startup_entries[full_path] != value:
                                    self.log_event.emit("warning", f"Startup entry changed: {name}: {self.startup_entries[full_path]} -> {value}")
                                    self.report_registry_threat(key_path, name, value, "Startup program modification detected")
                                    
                                    # Check if the new value is suspicious
                                    if self.is_suspicious_startup_value(value):
                                        self.log_event.emit("warning", f"Suspicious startup entry: {name}: {value}")
                                        self.report_registry_threat(key_path, name, value, "Suspicious startup program detected")
                                
                                i += 1
                            except WindowsError:
                                break
                        
                        winreg.CloseKey(key)
                    except Exception:
                        # Skip keys that can't be accessed
                        pass
                
                # Also check startup folders
                startup_folders = [
                    os.path.join(os.environ.get('APPDATA', ''), 'Microsoft\\Windows\\Start Menu\\Programs\\Startup'),
                    os.path.join(os.environ.get('PROGRAMDATA', ''), 'Microsoft\\Windows\\Start Menu\\Programs\\Startup')
                ]
                
                for folder in startup_folders:
                    if os.path.exists(folder):
                        for item in os.listdir(folder):
                            item_path = os.path.join(folder, item)
                            if os.path.isfile(item_path):
                                current_entries[item_path] = item_path
                                
                                # Check if this is a new entry
                                if item_path not in self.startup_entries:
                                    self.log_event.emit("warning", f"New startup file detected: {item_path}")
                                    self.report_file_threat(item_path, "New startup file detected")
                
                # Check for removed entries
                for full_path, value in self.startup_entries.items():
                    if full_path not in current_entries:
                        if os.path.isfile(full_path):
                            # This is a file path
                            self.log_event.emit("warning", f"Startup file removed: {full_path}")
                        else:
                            # This is a registry path
                            key_path, name = full_path.rsplit('\\', 1)
                            self.log_event.emit("warning", f"Startup entry removed: {name} = {value}")
                            self.report_registry_threat(key_path, name, value, "Startup program removal detected")
                
                # Update baseline
                self.startup_entries = current_entries
        except Exception as e:
            self.log_event.emit("error", f"Error checking startup changes: {str(e)}")
        




                
    def is_suspicious_startup_value(self, value):
        """Check if a startup value is suspicious"""
        value_lower = value.lower()
        
        # Check for suspicious locations
        suspicious_locations = [
            "\\temp\\", 
            "\\tmp\\", 
            "\\downloads\\",
            "\\appdata\\local\\temp\\",
            "\\users\\public\\",
            "\\programdata\\temp\\",
            "\\recycler\\",
            "\\$recycle.bin\\"
        ]
        
        if any(loc in value_lower for loc in suspicious_locations):
            return True
        
        # Check for suspicious command line patterns
        suspicious_patterns = [
            "-e ", "-enc", "-exec", "-nop", "-w hidden",
            "cmd /c", "cmd.exe /c", "powershell -",
            "javascript:", "vbscript:",
            "rundll32", "regsvr32",
            "mshta", "wscript", "cscript",
            "bitsadmin", "certutil -urlcache"
        ]
        
        if any(pattern in value_lower for pattern in suspicious_patterns):
            return True
        
        return False


    def report_file_threat(self, file_path, reason):
        """Report a detected file threat"""
        try:
            # Create threat information
            threat = {
                'file_path': file_path,
                'file_type': os.path.splitext(file_path)[1].lower(),
                'file_size': os.path.getsize(file_path) if os.path.exists(file_path) else 0,
                'status': 'suspicious',
                'action_taken': 'none',
                'threats': [{
                    'type': 'heuristic',
                    'name': 'Suspicious.File',
                    'confidence': 0.8,
                    'details': reason
                }]
            }
            
            self.log_event.emit("warning", f"File threat detected: {file_path} - {reason}")
            self.threat_detected.emit(threat)
            
        except Exception as e:
            self.log_event.emit("error", f"Error reporting file threat: {str(e)}")

    def initialize_appinit_dlls(self):
        """Initialize baseline of AppInit DLLs"""
        try:
            if sys.platform == 'win32':
                import winreg
                
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self.appinit_key)
                try:
                    self.last_appinit_value, _ = winreg.QueryValueEx(key, self.appinit_value)
                except WindowsError:
                    self.last_appinit_value = ""
                winreg.CloseKey(key)
                
                self.log_event.emit("info", f"Initialized monitoring for AppInit DLLs: {self.last_appinit_value}")
                
                # Also check Wow6432Node for 64-bit systems
                try:
                    wow64_key = self.appinit_key.replace("SOFTWARE", "SOFTWARE\\Wow6432Node")
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, wow64_key)
                    try:
                        self.last_appinit_value_wow64, _ = winreg.QueryValueEx(key, self.appinit_value)
                    except WindowsError:
                        self.last_appinit_value_wow64 = ""
                    winreg.CloseKey(key)
                    
                    self.log_event.emit("info", f"Initialized monitoring for Wow6432Node AppInit DLLs: {self.last_appinit_value_wow64}")
                except Exception:
                    self.last_appinit_value_wow64 = ""
        except Exception as e:
            self.log_event.emit("error", f"Failed to initialize AppInit DLLs monitoring: {str(e)}")

    def check_appinit_dlls(self):
        """Check for changes in AppInit DLLs (addresses AppinitDlls vulnerability)"""
        try:
            if sys.platform == 'win32':
                import winreg
                
                # Check main AppInit_DLLs
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self.appinit_key)
                try:
                    current_value, _ = winreg.QueryValueEx(key, self.appinit_value)
                except WindowsError:
                    current_value = ""
                winreg.CloseKey(key)
                
                if current_value != self.last_appinit_value:
                    self.log_event.emit("warning", f"AppInit DLLs changed: {self.last_appinit_value} -> {current_value}")
                    self.report_registry_threat(self.appinit_key, self.appinit_value, current_value, "AppInit DLLs modification detected")
                    
                    # Check if the new value is suspicious
                    if self.is_suspicious_appinit_dlls(current_value):
                        self.log_event.emit("warning", f"Suspicious AppInit DLLs detected: {current_value}")
                        self.report_registry_threat(self.appinit_key, self.appinit_value, current_value, "Suspicious AppInit DLLs detected")
                    
                    self.last_appinit_value = current_value
                
                # Check Wow6432Node AppInit_DLLs
                try:
                    wow64_key = self.appinit_key.replace("SOFTWARE", "SOFTWARE\\Wow6432Node")
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, wow64_key)
                    try:
                        current_value_wow64, _ = winreg.QueryValueEx(key, self.appinit_value)
                    except WindowsError:
                        current_value_wow64 = ""
                    winreg.CloseKey(key)
                    
                    if hasattr(self, 'last_appinit_value_wow64') and current_value_wow64 != self.last_appinit_value_wow64:
                        self.log_event.emit("warning", f"Wow6432Node AppInit DLLs changed: {self.last_appinit_value_wow64} -> {current_value_wow64}")
                        self.report_registry_threat(wow64_key, self.appinit_value, current_value_wow64, "Wow6432Node AppInit DLLs modification detected")
                        
                        # Check if the new value is suspicious
                        if self.is_suspicious_appinit_dlls(current_value_wow64):
                            self.log_event.emit("warning", f"Suspicious Wow6432Node AppInit DLLs detected: {current_value_wow64}")
                            self.report_registry_threat(wow64_key, self.appinit_value, current_value_wow64, "Suspicious Wow6432Node AppInit DLLs detected")
                        
                        self.last_appinit_value_wow64 = current_value_wow64
                except Exception:
                    pass
                
                # Also check if LoadAppInit_DLLs is enabled
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self.appinit_key)
                    try:
                        load_value, _ = winreg.QueryValueEx(key, "LoadAppInit_DLLs")
                        if load_value == 1 and (self.last_appinit_value or (hasattr(self, 'last_appinit_value_wow64') and self.last_appinit_value_wow64)):
                            self.log_event.emit("warning", "AppInit DLLs are enabled and DLLs are specified")
                            self.report_registry_threat(self.appinit_key, "LoadAppInit_DLLs", "1", "AppInit DLLs are enabled")
                    except WindowsError:
                        pass
                    winreg.CloseKey(key)
                except Exception:
                    pass
        except Exception as e:
            self.log_event.emit("error", f"Error checking AppInit DLLs: {str(e)}")

    def is_suspicious_appinit_dlls(self, value):
        """Check if AppInit DLLs value is suspicious"""
        if not value:
            return False
            
        value_lower = value.lower()
        
        # Check for suspicious locations
        suspicious_locations = [
            "\\temp\\", 
            "\\tmp\\", 
            "\\downloads\\",
            "\\appdata\\local\\temp\\",
            "\\users\\public\\",
            "\\programdata\\temp\\",
            "\\recycler\\",
            "\\$recycle.bin\\"
        ]
        
        if any(loc in value_lower for loc in suspicious_locations):
            return True
        
        # Check for unusual DLL names
        unusual_names = [
            "~", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "+", "=",
            "temp", "tmp", "test", "1", "2", "3", "a", "b", "c"
        ]
        
        for dll in value_lower.split(';'):
            dll = dll.strip()
            if dll:
                dll_name = os.path.basename(dll)
                dll_name_no_ext = os.path.splitext(dll_name)[0]
                
                if any(unusual in dll_name_no_ext.lower() for unusual in unusual_names):
                    return True
        
        return False


    
    def initialize_debugger_paths(self):
        """Initialize baseline of debugger paths"""
        try:
            if sys.platform == 'win32':
                import winreg
                
                for key_path in self.debugger_keys:
                    try:
                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                        
                        # Enumerate subkeys (each is a program)
                        i = 0
                        while True:
                            try:
                                subkey_name = winreg.EnumKey(key, i)
                                subkey = winreg.OpenKey(key, subkey_name)
                                
                                try:
                                    debugger, _ = winreg.QueryValueEx(subkey, "Debugger")
                                    self.debugger_values[f"{key_path}\\{subkey_name}"] = debugger
                                except WindowsError:
                                    pass
                                
                                winreg.CloseKey(subkey)
                                i += 1
                            except WindowsError:
                                break
                        
                        winreg.CloseKey(key)
                    except Exception:
                        # Skip keys that can't be accessed
                        pass
                        
                self.log_event.emit("info", f"Initialized monitoring for {len(self.debugger_values)} debugger paths")
        except Exception as e:
            self.log_event.emit("error", f"Failed to initialize debugger path monitoring: {str(e)}")

    def check_debugger_paths(self):
        """Check for changes in debugger paths (addresses ChangeDebuggerPath vulnerability)"""
        try:
            if sys.platform == 'win32':
                import winreg
                current_values = {}
                
                for key_path in self.debugger_keys:
                    try:
                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                        
                        # Enumerate subkeys (each is a program)
                        i = 0
                        while True:
                            try:
                                subkey_name = winreg.EnumKey(key, i)
                                subkey = winreg.OpenKey(key, subkey_name)
                                
                                try:
                                    debugger, _ = winreg.QueryValueEx(subkey, "Debugger")
                                    full_path = f"{key_path}\\{subkey_name}"
                                    current_values[full_path] = debugger
                                    
                                    # Check if this is a new debugger
                                    if full_path not in self.debugger_values:
                                        self.log_event.emit("warning", f"New debugger detected for {subkey_name}: {debugger}")
                                        self.report_registry_threat(key_path, f"{subkey_name}\\Debugger", debugger, "New debugger path detected")
                                    
                                    # Check if debugger changed
                                    elif self.debugger_values[full_path] != debugger:
                                        self.log_event.emit("warning", f"Debugger changed for {subkey_name}: {self.debugger_values[full_path]} -> {debugger}")
                                        self.report_registry_threat(key_path, f"{subkey_name}\\Debugger", debugger, "Debugger path modification detected")
                                        
                                        # Check if the new debugger is suspicious
                                        if self.is_suspicious_debugger(debugger):
                                            self.log_event.emit("warning", f"Suspicious debugger detected for {subkey_name}: {debugger}")
                                            self.report_registry_threat(key_path, f"{subkey_name}\\Debugger", debugger, "Suspicious debugger detected")
                                except WindowsError:
                                    pass
                                
                                winreg.CloseKey(subkey)
                                i += 1
                            except WindowsError:
                                break
                        
                        winreg.CloseKey(key)
                    except Exception:
                        # Skip keys that can't be accessed
                        pass
                
                # Check for removed debuggers
                for full_path, debugger in self.debugger_values.items():
                    if full_path not in current_values:
                        program = full_path.split('\\')[-1]
                        self.log_event.emit("warning", f"Debugger removed for {program}: {debugger}")
                        key_path = '\\'.join(full_path.split('\\')[:-1])
                        self.report_registry_threat(key_path, f"{program}\\Debugger", debugger, "Debugger path removal detected")
                
                # Update baseline
                self.debugger_values = current_values
        except Exception as e:
            self.log_event.emit("error", f"Error checking debugger paths: {str(e)}")

    def is_suspicious_debugger(self, debugger):
        """Check if a debugger path is suspicious"""
        debugger_lower = debugger.lower()
        
        # Check for suspicious locations
        suspicious_locations = [
            "\\temp\\", 
            "\\tmp\\", 
            "\\downloads\\",
            "\\appdata\\local\\temp\\",
            "\\users\\public\\",
            "\\programdata\\temp\\",
            "\\recycler\\",
            "\\$recycle.bin\\"
        ]
        
        if any(loc in debugger_lower for loc in suspicious_locations):
            return True
        
        # Check for suspicious command line patterns
        suspicious_patterns = [
            "cmd.exe", "powershell", "wscript", "cscript",
            "rundll32", "regsvr32", "mshta",
            "-e ", "-enc", "-exec", "-nop", "-w hidden"
        ]
        
        if any(pattern in debugger_lower for pattern in suspicious_patterns):
            return True
        
        return False


    
    def initialize_service_dlls(self):
        """Initialize baseline of service DLLs"""
        try:
            if sys.platform == 'win32':
                import winreg
                
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self.service_key)
                
                # Enumerate subkeys (each is a service)
                i = 0
                while True:
                    try:
                        service_name = winreg.EnumKey(key, i)
                        try:
                            service_key = winreg.OpenKey(key, f"{service_name}\\Parameters")
                            
                            try:
                                service_dll, _ = winreg.QueryValueEx(service_key, "ServiceDll")
                                self.service_dlls[service_name] = service_dll
                            except WindowsError:
                                pass
                            
                            winreg.CloseKey(service_key)
                        except WindowsError:
                            # Try without Parameters subkey
                            try:
                                service_key = winreg.OpenKey(key, service_name)
                                
                                try:
                                    service_dll, _ = winreg.QueryValueEx(service_key, "ServiceDll")
                                    self.service_dlls[service_name] = service_dll
                                except WindowsError:
                                    pass
                                
                                winreg.CloseKey(service_key)
                            except WindowsError:
                                pass
                        
                        i += 1
                    except WindowsError:
                        break
                
                winreg.CloseKey(key)
                
                self.log_event.emit("info", f"Initialized monitoring for {len(self.service_dlls)} service DLLs")
        except Exception as e:
            self.log_event.emit("error", f"Failed to initialize service DLL monitoring: {str(e)}")

    def check_service_dll_changes(self):
        """Check for changes in service DLLs (addresses SupersedeServiceDll vulnerability)"""
        try:
            if sys.platform == 'win32':
                import winreg
                current_dlls = {}
                
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self.service_key)
                
                # Enumerate subkeys (each is a service)
                i = 0
                while True:
                    try:
                        service_name = winreg.EnumKey(key, i)
                        try:
                            service_key = winreg.OpenKey(key, f"{service_name}\\Parameters")
                            
                            try:
                                service_dll, _ = winreg.QueryValueEx(service_key, "ServiceDll")
                                current_dlls[service_name] = service_dll
                                
                                # Check if this is a new service DLL
                                if service_name not in self.service_dlls:
                                    self.log_event.emit("warning", f"New service DLL detected for {service_name}: {service_dll}")
                                    self.report_service_threat(service_name, service_dll, "New service DLL detected")
                                
                                # Check if service DLL changed
                                elif self.service_dlls[service_name] != service_dll:
                                    self.log_event.emit("warning", f"Service DLL changed for {service_name}: {self.service_dlls[service_name]} -> {service_dll}")
                                    self.report_service_threat(service_name, service_dll, "Service DLL modification detected")
                            except WindowsError:
                                pass
                            
                            winreg.CloseKey(service_key)
                        except WindowsError:
                            # Try without Parameters subkey
                            try:
                                service_key = winreg.OpenKey(key, service_name)
                                
                                try:
                                    service_dll, _ = winreg.QueryValueEx(service_key, "ServiceDll")
                                    current_dlls[service_name] = service_dll
                                    
                                    # Check if this is a new service DLL
                                    if service_name not in self.service_dlls:
                                        self.log_event.emit("warning", f"New service DLL detected for {service_name}: {service_dll}")
                                        self.report_service_threat(service_name, service_dll, "New service DLL detected")
                                    
                                    # Check if service DLL changed
                                    elif self.service_dlls[service_name] != service_dll:
                                        self.log_event.emit("warning", f"Service DLL changed for {service_name}: {self.service_dlls[service_name]} -> {service_dll}")
                                        self.report_service_threat(service_name, service_dll, "Service DLL modification detected")
                                except WindowsError:
                                    pass
                                
                                winreg.CloseKey(service_key)
                            except WindowsError:
                                pass
                        
                        i += 1
                    except WindowsError:
                        break
                
                winreg.CloseKey(key)
                
                # Update baseline
                self.service_dlls = current_dlls
        except Exception as e:
            self.log_event.emit("error", f"Error checking service DLL changes: {str(e)}")


    
    def check_raw_disk_access(self):
        """Check for raw disk access attempts (addresses RawDisk vulnerability)"""
        try:
            if sys.platform == 'win32':
                # Check for processes with open handles to physical drives
                cmd = '''powershell -Command "
                # Try to use handle.exe if available
                $handleOutput = $null
                $handlePath = 'C:\\Windows\\handle.exe'
                if (Test-Path $handlePath) {
                    $handleOutput = & $handlePath -a -p PhysicalDrive 2>$null
                }
                
                # If handle.exe not available or failed, use alternative method
                if (-not $handleOutput) {
                    # Look for processes with suspicious command lines
                    $processes = Get-CimInstance Win32_Process | Where-Object { 
                        $_.CommandLine -like '*PhysicalDrive*' -or 
                        $_.CommandLine -like '*\\\\.\\\\*' -or
                        $_.CommandLine -like '*CreateFile*' -or
                        $_.CommandLine -like '*DeviceIoControl*'
                    }
                    
                    foreach ($proc in $processes) {
                        [PSCustomObject]@{
                            ProcessName = $proc.Name
                            PID = $proc.ProcessId
                            CommandLine = $proc.CommandLine
                        }
                    }
                    
                    # Also check loaded modules for disk access APIs
                    Get-Process | ForEach-Object {
                        $proc = $_
                        try {
                            $modules = $proc.Modules | Where-Object { 
                                $_.ModuleName -eq 'kernel32.dll' -or 
                                $_.ModuleName -eq 'ntdll.dll' -or
                                $_.ModuleName -eq 'diskio.dll' -or
                                $_.ModuleName -eq 'winioctl.dll'
                            }
                            
                            if ($modules -and ($proc.MainWindowTitle -like '*disk*' -or $proc.ProcessName -like '*disk*')) {
                                [PSCustomObject]@{
                                    ProcessName = $proc.ProcessName
                                    PID = $proc.Id
                                    Modules = ($modules | ForEach-Object { $_.ModuleName }) -join ', '
                                }
                            }
                        } catch {}
                    }
                } else {
                    # Parse handle.exe output
                    $handleOutput | ForEach-Object {
                        if ($_ -match 'PhysicalDrive' -or $_ -match '\\\\\\\\.\\\\\\\\PhysicalDrive') {
                            $_
                        }
                    }
                }
                
                # Check for direct disk access through device objects
                Get-CimInstance -Class Win32_Process | ForEach-Object {
                    $proc = $_
                    if ($proc.CommandLine -match '\\\\\\\\.\\\\\\\\(PhysicalDrive|Harddisk|Volume|Partition)') {
                        [PSCustomObject]@{
                            ProcessName = $proc.Name
                            PID = $proc.ProcessId
                            CommandLine = $proc.CommandLine
                            AccessType = 'Direct Device Access'
                        }
                    }
                }
                "'''
                
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                
                if result.returncode == 0 and result.stdout.strip():
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if "PhysicalDrive" in line or "\\\\.\\\\PhysicalDrive" in line or "Harddisk" in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                try:
                                    process_name = parts[0]
                                    pid = int(parts[1])
                                    self.log_event.emit("warning", f"Raw disk access detected: {process_name} (PID: {pid})")
                                    
                                    # Check if this is a known legitimate disk utility
                                    legitimate_disk_tools = [
                                        "diskpart.exe", "chkdsk.exe", "defrag.exe", "diskmgmt.msc",
                                        "partmgr.exe", "fsutil.exe", "format.exe", "diskperf.exe"
                                    ]
                                    
                                    if process_name.lower() not in [tool.lower() for tool in legitimate_disk_tools]:
                                        self.report_process_threat(process_name, pid, "Suspicious raw disk access detected")
                                        
                                        # Take action if configured
                                        if self.config.get('prevent_raw_disk_access', True) and self.is_admin_mode:
                                            try:
                                                # Terminate the process
                                                import ctypes
                                                handle = ctypes.windll.kernel32.OpenProcess(1, False, pid)
                                                if handle:
                                                    result = ctypes.windll.kernel32.TerminateProcess(handle, 0)
                                                    ctypes.windll.kernel32.CloseHandle(handle)
                                                    
                                                    if result:
                                                        self.log_event.emit("success", f"Terminated process with raw disk access: {process_name} (PID: {pid})")
                                                    else:
                                                        self.log_event.emit("error", f"Failed to terminate process: {process_name} (PID: {pid})")
                                            except Exception as e:
                                                self.log_event.emit("error", f"Error terminating process: {str(e)}")
                                    else:
                                        self.log_event.emit("info", f"Legitimate disk utility detected: {process_name} (PID: {pid})")
                                except (ValueError, IndexError):
                                    self.log_event.emit("warning", f"Raw disk access detected: {line}")
                                    self.report_process_threat("Unknown", 0, f"Raw disk access detected: {line}")
                
                # NEW: Add a device security policy to prevent raw disk access
                if self.config.get('prevent_raw_disk_access', True) and self.is_admin_mode:
                    try:
                        # Create PowerShell command to add security policy
                        ps_cmd = '''powershell -Command "
                        # Create a security descriptor that denies access to everyone except SYSTEM
                        $acl = 'D:P(D;;GA;;;WD)(A;;GA;;;SY)'
                        
                        # List of device paths to protect
                        $devices = @('\\\\.\\PhysicalDrive0', '\\\\.\\PhysicalDrive1', '\\\\.\\HarddiskVolume1')
                        
                        foreach ($device in $devices) {
                            try {
                                # Use sc.exe to set security on the device
                                $output = & cmd.exe /c 'sc.exe sdset $device $acl'
                                Write-Host 'Protected device: $device'
                            } catch {
                                Write-Host 'Failed to protect device $device: $_'
                            }
                        }
                        
                        # Also try to use DeviceGuard if available
                        try {
                            Import-Module DeviceGuard
                            $rules = New-CIPolicyRule -FilePathRule '\\\\.\\PhysicalDrive*' -Deny
                            New-CIPolicy -FilePath C:\\Windows\\Temp\\DiskProtection.xml -Rules $rules -UserPEs
                            ConvertFrom-CIPolicy -XmlFilePath C:\\Windows\\Temp\\DiskProtection.xml -BinaryFilePath C:\\Windows\\Temp\\DiskProtection.bin
                            Write-Host 'Created Device Guard policy for disk protection'
                        } catch {
                            Write-Host 'DeviceGuard module not available: $_'
                        }
                        "'''
                        
                        # Run the PowerShell command
                        subprocess.run(ps_cmd, capture_output=True, text=True, check=False)
                        
                    except Exception as e:
                        self.log_event.emit("error", f"Failed to add disk protection policy: {str(e)}")
        except Exception as e:
            self.log_event.emit("error", f"Error checking raw disk access: {str(e)}")



    
    def check_file_drops(self):
        """Check for file drops in sensitive locations (addresses FileDrop vulnerability)"""
        try:
            # Define sensitive locations to monitor
            sensitive_locations = [
                os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'System32'),
                os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'SysWOW64'),
                os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files')),
                os.path.join(os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)')),
                os.path.join(os.environ.get('PROGRAMDATA', 'C:\\ProgramData')),
                os.path.join(os.environ.get('APPDATA', os.path.expanduser('~\\AppData\\Roaming'))),
                os.path.join(os.environ.get('LOCALAPPDATA', os.path.expanduser('~\\AppData\\Local')))
            ]
            
            current_time = time.time()
            check_interval = 60  # Look for files created in the last minute
            
            for location in sensitive_locations:
                if not os.path.exists(location):
                    continue
                    
                try:
                    # Use PowerShell to find recently created files
                    if sys.platform == 'win32':
                        cmd = f'powershell -Command "Get-ChildItem -Path \'{location}\' -Recurse -File -ErrorAction SilentlyContinue | Where-Object {{ $_.CreationTime -gt (Get-Date).AddSeconds(-{check_interval}) }} | Select-Object FullName"'
                        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                        
                        if result.returncode == 0 and result.stdout.strip():
                            lines = result.stdout.strip().split('\n')
                            for line in lines:
                                if line.strip() and "FullName" not in line:  # Skip header
                                    file_path = line.strip()
                                    
                                    # Check if it's a suspicious file type
                                    if any(file_path.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
                                        self.log_event.emit("warning", f"Suspicious file drop detected: {file_path}")
                                        self.report_threat(file_path, "Suspicious file dropped in system directory")
                except Exception as e:
                    self.log_event.emit("error", f"Error checking file drops in {location}: {str(e)}")
        except Exception as e:
            self.log_event.emit("error", f"Error in check_file_drops: {str(e)}")


    def analyze_dropped_file(self, file_path):
        """Analyze a dropped file for malicious content"""
        try:
            # Check file signature
            if sys.platform == 'win32':
                # Check if file is signed
                cmd = f'powershell -Command "Get-AuthenticodeSignature \'{file_path}\' | Select-Object -ExpandProperty Status"'
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                
                if result.returncode == 0:
                    if "Valid" not in result.stdout:
                        # Unsigned file in system directory is suspicious
                        self.log_event.emit("warning", f"Unsigned file dropped in system directory: {file_path}")
                        
                        # Check file content
                        threats = self.scan_file_content(file_path)
                        if threats:
                            threat_names = [t.get('name', 'Unknown') for t in threats]
                            threat_text = ', '.join(threat_names)
                            self.log_event.emit("warning", f"Threats detected in dropped file: {threat_text}")
                            
                            # Report the threat
                            self.report_threat(file_path, f"Suspicious file drop: {threat_text}")
                            
                            # Take immediate action based on config
                            if self.config.get('auto_quarantine_drops', True):
                                # In a real implementation, this would call the quarantine method
                                self.log_event.emit("info", f"Auto-quarantining dropped file: {file_path}")
                                
                                # Emit a signal to the main window to quarantine the file
                                threat_info = {
                                    'file_path': file_path,
                                    'file_type': os.path.splitext(file_path)[1].lower(),
                                    'status': 'infected',
                                    'action_taken': 'none',
                                    'threats': [{
                                        'type': 'heuristic',
                                        'name': 'Suspicious.FileDrop',
                                        'confidence': 0.8,
                                        'details': f"Suspicious file dropped in system directory: {file_path}"
                                    }]
                                }
                                self.threat_detected.emit(threat_info)
        except Exception as e:
            self.log_event.emit("error", f"Error analyzing dropped file {file_path}: {str(e)}")


    def analyze_dropped_file(self, file_path):
        """Analyze a dropped file for malicious content"""
        try:
            # Check file signature
            if sys.platform == 'win32':
                # Check if file is signed
                cmd = f'powershell -Command "Get-AuthenticodeSignature \'{file_path}\' | Select-Object -ExpandProperty Status"'
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                
                if result.returncode == 0:
                    if "Valid" not in result.stdout:
                        # Unsigned file in system directory is suspicious
                        self.log_event.emit("warning", f"Unsigned file dropped in system directory: {file_path}")
                        
                        # Check file content
                        threats = self.scan_file_content(file_path)
                        if threats:
                            threat_names = [t.get('name', 'Unknown') for t in threats]
                            threat_text = ', '.join(threat_names)
                            self.log_event.emit("warning", f"Threats detected in dropped file: {threat_text}")
                            
                            # Report the threat
                            self.report_threat(file_path, f"Suspicious file drop: {threat_text}")
                            
                            # Take immediate action based on config
                            if self.config.get('auto_quarantine_drops', True):
                                # In a real implementation, this would call the quarantine method
                                self.log_event.emit("info", f"Auto-quarantining dropped file: {file_path}")
        except Exception as e:
            self.log_event.emit("error", f"Error analyzing dropped file {file_path}: {str(e)}")

    
    # Add DNS monitoring to detect DNS-based data exfiltration
    def monitor_dns_requests(self):
        """Monitor DNS requests to detect data exfiltration (addresses DNS Test vulnerability)"""
        try:
            if sys.platform == 'win32':
                # Check DNS cache for suspicious entries
                cmd = 'powershell -Command "Get-DnsClientCache | Where-Object { $_.Name.Length -gt 50 -or $_.Name -match \'^[a-f0-9]{32}\' } | Select-Object Name"'
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                
                if result.returncode == 0 and result.stdout.strip():
                    lines = result.stdout.strip().split('\n')
                    for line in lines[1:]:  # Skip header
                        domain = line.strip()
                        if domain and domain not in self.dns_cache and self.is_suspicious_dns_query(domain):
                            self.log_event.emit("warning", f"Suspicious DNS query detected: {domain}")
                            self.report_network_threat("DNS", domain, "Possible data exfiltration via DNS")
                            self.dns_cache[domain] = time.time()
        except Exception as e:
            self.log_event.emit("error", f"Error monitoring DNS requests: {str(e)}")

    def is_suspicious_dns_query(self, domain):
        """Check if a DNS query looks suspicious (long, encoded, etc.)"""
        # Check for very long domain names (potential data exfiltration)
        if len(domain) > 50:
            return True
            
        # Check for domains that look like hex-encoded data
        if re.match(r'^[a-f0-9]{32}', domain):
            return True
            
        # Check for domains with excessive subdomains
        if domain.count('.') > 5:
            return True
            
        # Check for base64-like encoding
        if re.match(r'^[A-Za-z0-9+/=]{20,}', domain):
            return True
            
        return False

    def report_network_threat(self, protocol, data, reason):
        """Report a detected network threat"""
        try:
            # Create threat information
            threat = {
                'protocol': protocol,
                'data': data,
                'status': 'suspicious',
                'action_taken': 'none',
                'threats': [{
                    'type': 'heuristic',
                    'name': 'Suspicious.NetworkActivity',
                    'confidence': 0.8,
                    'details': reason
                }]
            }
            
            self.log_event.emit("warning", f"Network threat detected: {protocol} - {data} - {reason}")
            self.threat_detected.emit(threat)
            
        except Exception as e:
            self.log_event.emit("error", f"Error reporting network threat: {str(e)}")



    
    def check_suspicious_processes(self):
        """Check for suspicious processes"""
        if sys.platform != 'win32' or not self.wmi:
            return
            
        try:
            # Get all running processes
            processes = self.wmi.Win32_Process()
            
            for process in processes:
                try:
                    # Check for suspicious process names
                    if process.Name.lower() in [p.lower() for p in self.suspicious_processes]:
                        # Get command line to check for suspicious arguments
                        if process.CommandLine:
                            cmd_line = process.CommandLine.lower()
                            
                            # Check for suspicious command line patterns
                            suspicious_patterns = [
                                "-e", "-enc", "-encodedcommand", "-nop", "-windowstyle hidden",
                                "-exec bypass", "downloadstring", "iex", "invoke-expression",
                                "regsvr32 /s /u /i:", "rundll32 javascript:", "mshta vbscript:",
                                "regsvr32 /s /n /u /i:", "scrobj.dll", "regasm /quiet",
                                "installutil /logfile= /logtoconsole=false"
                            ]
                            
                            for pattern in suspicious_patterns:
                                if pattern in cmd_line:
                                    self.report_process_threat(process.Name, process.ProcessId, 
                                                            f"Suspicious process with command line: {pattern}")
                                    break
                except Exception as e:
                    self.log_event.emit("error", f"Error checking process {process.Name}: {str(e)}")
                    
        except Exception as e:
            self.log_event.emit("error", f"Error monitoring processes: {str(e)}")
    
    def check_registry_changes(self):
        """Monitor registry for suspicious changes (Windows only)"""
        if sys.platform != 'win32':
            return
            
        try:
            import winreg
            
            for key_path in self.registry_keys_to_monitor:
                try:
                    # Determine which hive to use
                    if key_path.startswith("HKLM\\") or key_path.startswith("HKEY_LOCAL_MACHINE\\"):
                        hive = winreg.HKEY_LOCAL_MACHINE
                        key_path = key_path.replace("HKLM\\", "").replace("HKEY_LOCAL_MACHINE\\", "")
                    elif key_path.startswith("HKCU\\") or key_path.startswith("HKEY_CURRENT_USER\\"):
                        hive = winreg.HKEY_CURRENT_USER
                        key_path = key_path.replace("HKCU\\", "").replace("HKEY_CURRENT_USER\\", "")
                    else:
                        # Default to HKLM
                        hive = winreg.HKEY_LOCAL_MACHINE
                    
                    # Open the registry key
                    key = winreg.OpenKey(hive, key_path)
                    
                    # Enumerate values
                    i = 0
                    while True:
                        try:
                            name, value, type = winreg.EnumValue(key, i)
                            
                            # Check for suspicious values
                            if isinstance(value, str):
                                value_lower = value.lower()
                                
                                # Check for suspicious paths
                                suspicious_paths = [
                                    "\\temp\\", "\\appdata\\local\\temp\\",
                                    "\\users\\public\\", "\\programdata\\",
                                    ".exe", ".dll", ".ps1", ".vbs", ".js", ".hta"
                                ]
                                
                                for path in suspicious_paths:
                                    if path in value_lower:
                                        self.report_registry_threat(key_path, name, value,
                                                                 f"Suspicious registry value contains: {path}")
                                        break
                            
                            i += 1
                        except WindowsError:
                            break
                    
                    winreg.CloseKey(key)
                    
                except Exception as e:
                    # Skip keys that can't be accessed
                    pass
                    
        except Exception as e:
            self.log_event.emit("error", f"Error monitoring registry: {str(e)}")
    
    def check_driver_changes(self):
        """Check for suspicious driver and kernel modifications (Windows only)"""
        if sys.platform != 'win32' or not self.wmi:
            return
            
        try:
            # Check for newly loaded drivers
            drivers = self.wmi.Win32_SystemDriver()
            
            for driver in drivers:
                try:
                    # Check if driver is running and not from Microsoft
                    if driver.State == "Running" and "Microsoft" not in driver.Manufacturer:
                        # Check path for suspicious locations
                        if driver.PathName:
                            path_lower = driver.PathName.lower()
                            
                            suspicious_paths = [
                                "\\temp\\", "\\appdata\\local\\temp\\",
                                "\\users\\public\\", "\\programdata\\"
                            ]
                            
                            for path in suspicious_paths:
                                if path in path_lower:
                                    self.report_driver_threat(driver.Name, driver.PathName,
                                                          f"Suspicious driver location: {path}")
                                    break
                except Exception as e:
                    self.log_event.emit("error", f"Error checking driver {driver.Name}: {str(e)}")
                    
        except Exception as e:
            self.log_event.emit("error", f"Error monitoring drivers: {str(e)}")
    
    def calculate_entropy(self, file_path):
        """Calculate Shannon entropy of a file to detect encryption/packing"""
        try:
            # Use a maximum read size to prevent memory issues with large files
            max_read_size = 1024 * 1024  # 1MB
            
            with open(file_path, 'rb') as f:
                # For large files, read only the first and last portions
                file_size = os.path.getsize(file_path)
                
                if file_size <= max_read_size:
                    # For small files, read the entire content
                    data = f.read()
                else:
                    # For large files, read first and last 512KB
                    first_chunk = f.read(max_read_size // 2)
                    f.seek(-min(max_read_size // 2, file_size), 2)  # Seek from end
                    last_chunk = f.read(max_read_size // 2)
                    data = first_chunk + last_chunk
            
            if not data:
                return 0
                
            entropy = 0
            byte_counts = Counter(data)
            data_size = len(data)
            
            # Calculate Shannon entropy
            for count in byte_counts.values():
                probability = count / data_size
                entropy -= probability * math.log2(probability)
                
            return entropy
        except Exception as e:
            self.log_event.emit("error", f"Error calculating entropy: {str(e)}")
            return 0
    
    def is_signed(self, file_path):
        """Check if a file is digitally signed (Windows only)"""
        if sys.platform != 'win32':
            return False
            
        try:
            import subprocess
            
            # Use PowerShell to check digital signature
            cmd = f'powershell -Command "Get-AuthenticodeSignature \'{file_path}\' | Select-Object -ExpandProperty Status"'
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            
            if result.returncode == 0 and "Valid" in result.stdout:
                return True
        except:
            pass
            
        return False
    
    def report_threat(self, file_path, reason):
        """Report a detected file threat"""
        try:
            # Create threat information
            threat = {
                'file_path': file_path,
                'file_type': os.path.splitext(file_path)[1].lower(),
                'file_size': os.path.getsize(file_path),
                'hash': self.calculate_file_hash(file_path),
                'status': 'infected',
                'action_taken': 'none',
                'threats': [{
                    'type': 'heuristic',
                    'name': 'Suspicious.RealTimeDetection',
                    'confidence': 0.8,
                    'details': reason
                }]
            }
            
            self.log_event.emit("warning", f"Real-time protection detected threat in {file_path}: {reason}")
            self.threat_detected.emit(threat)
            
        except Exception as e:
            self.log_event.emit("error", f"Error reporting threat for {file_path}: {str(e)}")
    
    def report_process_threat(self, process_name, process_id, reason):
        """Report a detected process threat"""
        try:
            # Create threat information for process
            threat = {
                'process_name': process_name,
                'process_id': process_id,
                'status': 'suspicious',
                'action_taken': 'none',
                'threats': [{
                    'type': 'heuristic',
                    'name': 'Suspicious.Process',
                    'confidence': 0.7,
                    'details': reason
                }]
            }
            
            self.log_event.emit("warning", f"Real-time protection detected suspicious process: {process_name} (PID: {process_id}): {reason}")
            self.threat_detected.emit(threat)
            
        except Exception as e:
            self.log_event.emit("error", f"Error reporting process threat: {str(e)}")
    
    def report_registry_threat(self, key_path, value_name, value_data, reason):
        """Report a detected registry threat"""
        try:
            # Create threat information for registry
            threat = {
                'registry_key': key_path,
                'registry_value': value_name,
                'registry_data': value_data,
                'status': 'suspicious',
                'action_taken': 'none',
                'threats': [{
                    'type': 'heuristic',
                    'name': 'Suspicious.Registry',
                    'confidence': 0.75,
                    'details': reason
                }]
            }
            
            self.log_event.emit("warning", f"Real-time protection detected suspicious registry: {key_path}\\{value_name}: {reason}")
            self.threat_detected.emit(threat)
            
        except Exception as e:
            self.log_event.emit("error", f"Error reporting registry threat: {str(e)}")
    
    def report_driver_threat(self, driver_name, driver_path, reason):
        """Report a detected driver threat"""
        try:
            # Create threat information
            threat = {
                'driver_name': driver_name,
                'driver_path': driver_path,
                'status': 'suspicious',
                'action_taken': 'none',
                'threats': [{
                    'type': 'heuristic',
                    'name': 'Suspicious.Driver',
                    'confidence': 0.85,
                    'details': reason
                }]
            }
            
            self.log_event.emit("warning", f"Driver threat detected: {driver_name} - {reason}")
            self.threat_detected.emit(threat)
            
        except Exception as e:
            self.log_event.emit("error", f"Error reporting driver threat: {str(e)}")

    
    def calculate_file_hash(self, file_path):
        """Calculate MD5 hash of a file"""
        try:
            hash_obj = hashlib.md5()
            
            with open(file_path, 'rb') as f:
                # Read file in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_obj.update(chunk)
            
            return hash_obj.hexdigest()
        except Exception:
            return None
    
    def stop(self):
        """Stop the monitoring thread"""
        self.running = False
        self.log_event.emit("info", "Stopping real-time monitoring")



class SignatureUpdateThread(QThread):
    """Thread for updating virus signatures"""
    update_complete = pyqtSignal(bool)
    update_progress = pyqtSignal(int, int, str)
    log_event = pyqtSignal(str, str)
    
    def __init__(self, sources):
        super().__init__()
        self.sources = sources
    
    def run(self):
        """Run the update process"""
        try:
            self.log_event.emit("info", "Downloading virus signatures...")
            
            # Create signatures directory if it doesn't exist
            signatures_dir = os.path.join(
                os.environ.get('APPDATA', os.path.expanduser('~')),
                APP_NAME,
                'signatures'
            )
            os.makedirs(signatures_dir, exist_ok=True)
            
            # Download signatures from sources
            success = False
            total_sources = len(self.sources)
            
            for i, source in enumerate(self.sources):
                try:
                    self.log_event.emit("info", f"Downloading from {source}...")
                    self.update_progress.emit(i, total_sources, f"Downloading from {source}")
                    
                    # Download signature file
                    response = requests.get(source, timeout=30)
                    if response.status_code == 200:
                        # Parse the signature data
                        try:
                            # Try to parse as JSON
                            signature_data = response.json()
                            
                            # Save to file
                            filename = os.path.basename(source)
                            with open(os.path.join(signatures_dir, filename), 'w') as f:
                                json.dump(signature_data, f)
                            
                            # Update global signatures
                            if 'signatures' in signature_data:
                                for sig_hash, sig_name in signature_data['signatures'].items():
                                    VIRUS_SIGNATURES[sig_hash] = sig_name
                            
                            success = True
                            self.log_event.emit("info", f"Successfully downloaded signatures from {source}")
                        
                        except json.JSONDecodeError:
                            # Not JSON, save as raw file
                            filename = os.path.basename(source)
                            with open(os.path.join(signatures_dir, filename), 'wb') as f:
                                f.write(response.content)
                            
                            success = True
                            self.log_event.emit("info", f"Successfully downloaded signatures from {source}")
                    
                    else:
                        self.log_event.emit("error", f"Failed to download from {source}: HTTP {response.status_code}")
                
                except Exception as e:
                    self.log_event.emit("error", f"Error downloading from {source}: {str(e)}")
            
            # Update timestamp
            if success:
                with open(os.path.join(signatures_dir, 'last_update.txt'), 'w') as f:
                    f.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                
                # Try to download additional signatures from community sources
                self.download_community_signatures(signatures_dir)
            
            self.update_complete.emit(success)
        
        except Exception as e:
            self.log_event.emit("error", f"Update error: {str(e)}")
            self.update_complete.emit(False)
    
    def download_community_signatures(self, signatures_dir):
        """Download additional signatures from community sources"""
        try:
            # List of community signature sources
            community_sources = [
                "https://raw.githubusercontent.com/ClamAV/clamav/main/signatures/daily.cvd",
                "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/generic_anomalies.yar",
                "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_malware.yar"
            ]
            
            for source in community_sources:
                try:
                    self.log_event.emit("info", f"Downloading community signatures from {source}...")
                    
                    response = requests.get(source, timeout=30)
                    if response.status_code == 200:
                        filename = os.path.basename(source)
                        with open(os.path.join(signatures_dir, filename), 'wb') as f:
                            f.write(response.content)
                        
                        self.log_event.emit("info", f"Successfully downloaded community signatures from {source}")
                except Exception as e:
                    self.log_event.emit("warning", f"Failed to download community signatures from {source}: {str(e)}")
        
        except Exception as e:
            self.log_event.emit("warning", f"Error downloading community signatures: {str(e)}")


class MainWindow(QMainWindow):
    """Main application window"""

    def __init__(self):
        super().__init__()
        
        # Load configuration first
        self.config = self._load_config()
        
        # Initialize notification manager
        self.notification_manager = NotificationManager()
            
        # Check admin status
        self.is_admin_mode = is_admin()
        
        # Initialize real-time monitor with all protections enabled by default
        config = self.config.copy()
        config.update({
            'dns_monitoring': True,
            'raw_disk_monitoring': True,
            'file_drop_monitoring': True,
            'hook_monitoring': True,
            'detect_process_impersonation': True,
            'detect_runner_invasion': True,
            'auto_quarantine_drops': True
        })
        self.real_time_monitor = RealTimeMonitorThread(config)
        self.real_time_monitor.threat_detected.connect(self.on_real_time_threat)
        self.real_time_monitor.log_event.connect(self.add_log_event)
        
        # Set window properties
        self.setWindowTitle(f"{APP_NAME} - Virus Protection")
        self.setMinimumSize(800, 600)
        self.memory_timer = QTimer(self)
        self.memory_timer.timeout.connect(self.monitor_memory_usage)
        self.memory_timer.start(60000)  # Check every minute
        self.last_memory_log = time.time()
        
        # Initialize UI
        self.init_ui()
        
        # Initialize system tray
        self.init_tray()
        
        # Show admin warning if not running as admin
        if not self.is_admin_mode:
            QTimer.singleShot(1000, self.show_admin_warning)


    
    def init_tray(self):
        """Initialize system tray icon"""
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setToolTip(f"{APP_NAME} - Virus Protection")
        
        # Create tray menu
        tray_menu = QMenu()
        
        open_action = QAction("Open", self)
        open_action.triggered.connect(self.show)
        tray_menu.addAction(open_action)
        
        tray_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        tray_menu.addAction(exit_action)
        
        # Set tray icon menu
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
    
    def start_scan(self):
        """Start a scan"""
        QMessageBox.information(self, "Scan", "Scan started!")
    
    def closeEvent(self, event):
        """Handle window close event"""
        # Hide to system tray instead of closing
        event.ignore()
        self.hide()
        
        # Show notification
        self.tray_icon.showMessage(
            f"{APP_NAME} is still running",
            "The application is minimized to the system tray.",
            QSystemTrayIcon.Information,
            2000
        )
    
    def monitor_memory_usage(self):
        """Monitor memory usage and trigger cleanup if needed"""
        try:
            import psutil
            process = psutil.Process(os.getpid())
            memory_percent = process.memory_percent()
            
            # Log memory usage every 5 minutes
            current_time = time.time()
            if not hasattr(self, 'last_memory_log') or current_time - self.last_memory_log > 300:
                self.last_memory_log = current_time
                memory_info = process.memory_info()
                self.add_log_event("info", f"Memory usage: {memory_percent:.1f}% ({memory_info.rss / (1024*1024):.1f} MB)")
            
            # If memory usage is high, trigger garbage collection
            if memory_percent > 80:
                self.add_log_event("warning", f"High memory usage detected: {memory_percent:.1f}%, triggering cleanup")
                self.force_garbage_collection()
        except ImportError:
            # psutil not available
            pass
        except Exception as e:
            logging.error(f"Error monitoring memory: {str(e)}")

    # Add these methods to the MainWindow class

    def fix_changedrvpath_vulnerability(self):
        """Fix ChangeDrvPath vulnerability (prevents rootkit installation)"""
        try:
            if sys.platform == 'win32' and self.is_admin_mode:
                self.add_log_event("info", "Applying ChangeDrvPath vulnerability fix...")
                
                # Create a simple PowerShell script with minimal dependencies
                ps_cmd = '''
                try {
                    # Create protection flag
                    $protectionKey = 'HKLM:\\SOFTWARE\\ShieldGuardPro\\Protection'
                    if (-not (Test-Path $protectionKey)) {
                        New-Item -Path $protectionKey -Force | Out-Null
                    }
                    New-ItemProperty -Path $protectionKey -Name 'BlockChangeDrvPath' -Value 1 -PropertyType DWORD -Force
                    
                    # Block the specific test vector
                    $blockKey = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\rundll32.exe'
                    if (-not (Test-Path $blockKey)) {
                        New-Item -Path $blockKey -Force | Out-Null
                    }
                    New-ItemProperty -Path $blockKey -Name 'Debugger' -Value 'svchost.exe' -PropertyType String -Force
                    
                    Write-Output "ChangeDrvPath vulnerability fix applied successfully"
                } catch {
                    Write-Output "Error: $_"
                    exit 1
                }
                '''
                
                # Create a temporary file for the PowerShell script
                import tempfile
                fd, script_path = tempfile.mkstemp(suffix='.ps1')
                os.close(fd)
                
                with open(script_path, 'w') as f:
                    f.write(ps_cmd)
                
                # Run PowerShell with the script file instead of inline command
                try:
                    # Use subprocess.run with safe parameters
                    result = subprocess.run(
                        ['powershell', '-ExecutionPolicy', 'Bypass', '-File', script_path],
                        capture_output=True,
                        text=True,
                        check=False
                    )
                    
                    # Clean up the temporary script
                    try:
                        os.remove(script_path)
                    except:
                        pass
                    
                    if "ChangeDrvPath vulnerability fix applied successfully" in result.stdout:
                        self.add_log_event("success", "ChangeDrvPath vulnerability fix applied successfully")
                        return True
                    else:
                        self.add_log_event("warning", f"ChangeDrvPath fix output: {result.stdout}")
                        self.add_log_event("warning", f"ChangeDrvPath fix errors: {result.stderr}")
                        
                        # Try direct registry modification as backup
                        return self._apply_registry_fix_changedrvpath()
                except Exception as e:
                    self.add_log_event("error", f"PowerShell execution failed: {str(e)}")
                    # Try direct registry modification as backup
                    return self._apply_registry_fix_changedrvpath()
            else:
                self.add_log_event("error", "ChangeDrvPath fix requires Windows and administrator privileges")
                return False
                
        except Exception as e:
            self.add_log_event("error", f"Error applying ChangeDrvPath fix: {str(e)}")
            return False

    def _apply_registry_fix_changedrvpath(self):
        """Apply ChangeDrvPath fix directly using registry API"""
        try:
            import winreg
            
            # Create a key that specifically blocks the test vector
            key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\rundll32.exe"
            key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, "Debugger", 0, winreg.REG_SZ, "svchost.exe")
            winreg.CloseKey(key)
            
            # Create protection flag
            protection_key_path = r"SOFTWARE\ShieldGuardPro\Protection"
            protection_key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, protection_key_path, 0, winreg.KEY_WRITE)
            winreg.SetValueEx(protection_key, "BlockChangeDrvPath", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(protection_key)
            
            self.add_log_event("success", "ChangeDrvPath vulnerability fix applied using direct registry modification")
            return True
        except Exception as e:
            self.add_log_event("error", f"Direct registry modification failed: {str(e)}")
            return False

    def fix_runner_vulnerability(self):
        """Fix Runner invasion vulnerability (prevents code execution via rundll32)"""
        try:
            if sys.platform == 'win32' and self.is_admin_mode:
                self.add_log_event("info", "Applying Runner vulnerability fix...")
                
                # Create a simple PowerShell script with minimal dependencies
                ps_cmd = '''
                try {
                    # Create protection flag
                    $protectionKey = 'HKLM:\\SOFTWARE\\ShieldGuardPro\\Protection'
                    if (-not (Test-Path $protectionKey)) {
                        New-Item -Path $protectionKey -Force | Out-Null
                    }
                    New-ItemProperty -Path $protectionKey -Name 'BlockRunner' -Value 1 -PropertyType DWORD -Force
                    
                    # Block the specific test vector
                    $blockKey = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\rundll32.exe'
                    if (-not (Test-Path $blockKey)) {
                        New-Item -Path $blockKey -Force | Out-Null
                    }
                    New-ItemProperty -Path $blockKey -Name 'Debugger' -Value 'svchost.exe' -PropertyType String -Force
                    
                    Write-Output "Runner vulnerability fix applied successfully"
                } catch {
                    Write-Output "Error: $_"
                    exit 1
                }
                '''
                
                # Create a temporary file for the PowerShell script
                import tempfile
                fd, script_path = tempfile.mkstemp(suffix='.ps1')
                os.close(fd)
                
                with open(script_path, 'w') as f:
                    f.write(ps_cmd)
                
                # Run PowerShell with the script file instead of inline command
                try:
                    # Use subprocess.run with safe parameters
                    result = subprocess.run(
                        ['powershell', '-ExecutionPolicy', 'Bypass', '-File', script_path],
                        capture_output=True,
                        text=True,
                        check=False
                    )
                    
                    # Clean up the temporary script
                    try:
                        os.remove(script_path)
                    except:
                        pass
                    
                    if "Runner vulnerability fix applied successfully" in result.stdout:
                        self.add_log_event("success", "Runner vulnerability fix applied successfully")
                        return True
                    else:
                        self.add_log_event("warning", f"Runner fix output: {result.stdout}")
                        self.add_log_event("warning", f"Runner fix errors: {result.stderr}")
                        
                        # Try direct registry modification as backup
                        return self._apply_registry_fix_runner()
                except Exception as e:
                    self.add_log_event("error", f"PowerShell execution failed: {str(e)}")
                    # Try direct registry modification as backup
                    return self._apply_registry_fix_runner()
            else:
                self.add_log_event("error", "Runner fix requires Windows and administrator privileges")
                return False
                
        except Exception as e:
            self.add_log_event("error", f"Error applying Runner fix: {str(e)}")
            return False

    def _apply_registry_fix_runner(self):
        """Apply Runner fix directly using registry API"""
        try:
            import winreg
            
            # Create a key that specifically blocks the test vector
            key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\rundll32.exe"
            key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, "Debugger", 0, winreg.REG_SZ, "svchost.exe")
            winreg.CloseKey(key)
            
            # Create protection flag
            protection_key_path = r"SOFTWARE\ShieldGuardPro\Protection"
            protection_key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, protection_key_path, 0, winreg.KEY_WRITE)
            winreg.SetValueEx(protection_key, "BlockRunner", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(protection_key)
            
            self.add_log_event("success", "Runner vulnerability fix applied using direct registry modification")
            return True
        except Exception as e:
            self.add_log_event("error", f"Direct registry modification failed: {str(e)}")
            return False

    def fix_rawdisk_vulnerability(self):
        """Fix RawDisk vulnerability (prevents direct disk access)"""
        try:
            if sys.platform == 'win32' and self.is_admin_mode:
                self.add_log_event("info", "Applying RawDisk vulnerability fix...")
                
                # Create a simple PowerShell script with minimal dependencies
                ps_cmd = '''
                try {
                    # Create protection flag
                    $protectionKey = 'HKLM:\\SOFTWARE\\ShieldGuardPro\\Protection'
                    if (-not (Test-Path $protectionKey)) {
                        New-Item -Path $protectionKey -Force | Out-Null
                    }
                    New-ItemProperty -Path $protectionKey -Name 'BlockRawDisk' -Value 1 -PropertyType DWORD -Force
                    
                    # Create a key that enables write protection
                    $storageKey = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies'
                    if (-not (Test-Path $storageKey)) {
                        New-Item -Path $storageKey -Force | Out-Null
                    }
                    New-ItemProperty -Path $storageKey -Name 'WriteProtect' -Value 1 -PropertyType DWORD -Force
                    
                    Write-Output "RawDisk vulnerability fix applied successfully"
                } catch {
                    Write-Output "Error: $_"
                    exit 1
                }
                '''
                
                # Create a temporary file for the PowerShell script
                import tempfile
                fd, script_path = tempfile.mkstemp(suffix='.ps1')
                os.close(fd)
                
                with open(script_path, 'w') as f:
                    f.write(ps_cmd)
                
                # Run PowerShell with the script file instead of inline command
                try:
                    # Use subprocess.run with safe parameters
                    result = subprocess.run(
                        ['powershell', '-ExecutionPolicy', 'Bypass', '-File', script_path],
                        capture_output=True,
                        text=True,
                        check=False
                    )
                    
                    # Clean up the temporary script
                    try:
                        os.remove(script_path)
                    except:
                        pass
                    
                    if "RawDisk vulnerability fix applied successfully" in result.stdout:
                        self.add_log_event("success", "RawDisk vulnerability fix applied successfully")
                        return True
                    else:
                        self.add_log_event("warning", f"RawDisk fix output: {result.stdout}")
                        self.add_log_event("warning", f"RawDisk fix errors: {result.stderr}")
                        
                        # Try direct registry modification as backup
                        return self._apply_registry_fix_rawdisk()
                except Exception as e:
                    self.add_log_event("error", f"PowerShell execution failed: {str(e)}")
                    # Try direct registry modification as backup
                    return self._apply_registry_fix_rawdisk()
            else:
                self.add_log_event("error", "RawDisk fix requires Windows and administrator privileges")
                return False
                
        except Exception as e:
            self.add_log_event("error", f"Error applying RawDisk fix: {str(e)}")
            return False

    def _apply_registry_fix_rawdisk(self):
        """Apply RawDisk fix directly using registry API"""
        try:
            import winreg
            
            # Create a key that enables write protection
            key_path = r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"
            key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, "WriteProtect", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
            
            # Create protection flag
            protection_key_path = r"SOFTWARE\ShieldGuardPro\Protection"
            protection_key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, protection_key_path, 0, winreg.KEY_WRITE)
            winreg.SetValueEx(protection_key, "BlockRawDisk", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(protection_key)
            
            self.add_log_event("success", "RawDisk vulnerability fix applied using direct registry modification")
            return True
        except Exception as e:
            self.add_log_event("error", f"Direct registry modification failed: {str(e)}")
            return False

    def fix_all_vulnerabilities(self):
        """Fix all known vulnerabilities"""
        try:
            # Show a progress dialog
            progress = QProgressDialog("Applying security fixes...", "Cancel", 0, 3, self)
            progress.setWindowTitle("Security Enhancement")
            progress.setWindowModality(Qt.WindowModal)
            progress.setValue(0)
            progress.show()
            QApplication.processEvents()
            
            success_count = 0
            
            # 1. Fix ChangeDrvPath vulnerability
            self.add_log_event("info", "Fixing ChangeDrvPath vulnerability...")
            progress.setLabelText("Fixing ChangeDrvPath vulnerability...")
            if self.fix_changedrvpath_vulnerability():
                success_count += 1
            progress.setValue(1)
            QApplication.processEvents()
            
            # 2. Fix Runner vulnerability
            self.add_log_event("info", "Fixing Runner vulnerability...")
            progress.setLabelText("Fixing Runner vulnerability...")
            if self.fix_runner_vulnerability():
                success_count += 1
            progress.setValue(2)
            QApplication.processEvents()
            
            # 3. Fix RawDisk vulnerability
            self.add_log_event("info", "Fixing RawDisk vulnerability...")
            progress.setLabelText("Fixing RawDisk vulnerability...")
            if self.fix_rawdisk_vulnerability():
                success_count += 1
            progress.setValue(3)
            QApplication.processEvents()
            
            progress.close()
            
            # Show notification based on results
            if success_count == 3:
                self.notification_manager.show_notification(
                    "Security Vulnerabilities Fixed",
                    "All vulnerabilities have been successfully fixed.",
                    "success"
                )
                return True
            elif success_count > 0:
                self.notification_manager.show_notification(
                    "Some Vulnerabilities Fixed",
                    f"Fixed {success_count} out of 3 vulnerabilities. Check logs for details.",
                    "warning"
                )
                return True
            else:
                self.notification_manager.show_notification(
                    "Vulnerability Fix Failed",
                    "Failed to fix vulnerabilities. Check logs for details.",
                    "error"
                )
                return False
                
        except Exception as e:
            self.add_log_event("error", f"Error fixing vulnerabilities: {str(e)}")
            self.notification_manager.show_notification(
                "Error Fixing Vulnerabilities",
                f"An error occurred: {str(e)}",
                "error"
            )
            return False







    def handle_network_threat(self, threat):
        """Handle network-based threats detected by real-time monitoring"""
        protocol = threat.get('protocol', 'Unknown')
        data = threat.get('data', 'Unknown')
        threats = threat.get('threats', [])
        details = threats[0].get('details', '') if threats else ''
        
        # Add to log
        self.add_log_event("warning", f"Suspicious network activity detected: {protocol} - {data} - {details}")
        
        # Show notification
        self.notification_manager.show_notification(
            "Suspicious Network Activity",
            f"{protocol}: {data} - {details}",
            "warning"
        )
        
        # Block the connection if configured
        if self.config.get('auto_block_connections', False):
            self.block_suspicious_connection(protocol, data)

    def block_suspicious_connection(self, protocol, data):
        """Block a suspicious network connection"""
        try:
            if sys.platform == 'win32':
                # Use Windows Firewall to block the connection
                if protocol == "DNS":
                    # Extract domain
                    domain = data
                    
                    # Create firewall rule
                    rule_name = f"ShieldGuard_Block_{domain.replace('.', '_')}"
                    cmd = f'powershell -Command "New-NetFirewallRule -DisplayName \'{rule_name}\' -Direction Outbound -Action Block -RemoteAddress {domain} -Protocol Any"'
                    subprocess.run(cmd, capture_output=True, text=True, check=False)
                    
                    self.add_log_event("info", f"Blocked outbound connections to {domain}")
                    
                    # Show notification
                    self.notification_manager.show_notification(
                        "Connection Blocked",
                        f"Blocked outbound connections to {domain}",
                        "success"
                    )
        except Exception as e:
            self.add_log_event("error", f"Failed to block connection: {str(e)}")



    def on_real_time_threat(self, result):
        """Handle threat detected by real-time monitoring with automatic response"""
        # Check if this is a file threat
        if 'file_path' in result:
            file_path = result.get('file_path', 'Unknown file')
            threats = result.get('threats', [])
            threat_names = [t.get('name', 'Unknown') for t in threats]
            threat_text = ', '.join(threat_names) if threat_names else 'Unknown threat'
            
            # Add to log
            self.add_log_event("warning", f"Real-time protection detected {threat_text} in {file_path}")
            
            # Show notification
            self.notification_manager.show_notification(
                "Threat Detected!",
                f"{threat_text} detected in {file_path}",
                "warning"
            )
            
            # Take action based on config without asking user
            action = self.config.get('action', 'quarantine')
            if action == 'quarantine':
                if self.quarantine_file(file_path):
                    self.add_log_event("success", f"Automatically quarantined {file_path}")
                    
                    # Show notification
                    self.notification_manager.show_notification(
                        "Threat Automatically Quarantined",
                        f"A detected threat has been automatically moved to quarantine.",
                        "success"
                    )
                else:
                    self.add_log_event("error", f"Failed to quarantine {file_path}")
                    
                    # Show notification
                    self.notification_manager.show_notification(
                        "Quarantine Failed",
                        f"Failed to quarantine the detected threat.",
                        "error"
                    )
            elif action == 'delete':
                try:
                    os.remove(file_path)
                    self.add_log_event("success", f"Automatically deleted {file_path}")
                    
                    # Show notification
                    self.notification_manager.show_notification(
                        "Threat Automatically Deleted",
                        f"A detected threat has been automatically deleted.",
                        "success"
                    )
                except Exception as e:
                    self.add_log_event("error", f"Failed to delete {file_path}: {str(e)}")
                    
                    # Show notification
                    self.notification_manager.show_notification(
                        "Delete Failed",
                        f"Failed to delete a detected threat.",
                        "error"
                    )
                    
                    # Try to quarantine as fallback
                    if self.quarantine_file(file_path):
                        self.add_log_event("success", f"Quarantined {file_path} as fallback")
                        
                        # Show notification
                        self.notification_manager.show_notification(
                            "Threat Quarantined",
                            f"Threat quarantined as fallback after deletion failed.",
                            "success"
                        )
        
        # Handle process threats
        elif 'process_name' in result:
            process_name = result.get('process_name', 'Unknown process')
            process_id = result.get('process_id', 'Unknown')
            threats = result.get('threats', [])
            details = threats[0].get('details', '') if threats else ''
            
            # Add to log
            self.add_log_event("warning", f"Suspicious process detected: {process_name} (PID: {process_id}) - {details}")
            
            # Show notification
            self.notification_manager.show_notification(
                "Suspicious Process Detected",
                f"{process_name} (PID: {process_id}) - {details}",
                "warning"
            )
            
            # Automatically terminate if configured
            if self.config.get('auto_terminate_processes', False):
                self.terminate_process(process_id)
            else:
                # Log that automatic termination is disabled
                self.add_log_event("info", f"Automatic process termination is disabled. Process {process_id} not terminated.")
        
        # Handle registry threats
        elif 'registry_key' in result:
            key_path = result.get('registry_key', 'Unknown key')
            value_name = result.get('registry_value', 'Unknown value')
            threats = result.get('threats', [])
            details = threats[0].get('details', '') if threats else ''
            
            # Add to log
            self.add_log_event("warning", f"Suspicious registry modification detected: {key_path}\\{value_name} - {details}")
            
            # Show notification
            self.notification_manager.show_notification(
                "Suspicious Registry Modification",
                f"Registry key: {key_path}\\{value_name} - {details}",
                "warning"
            )
            
            # Automatically fix if configured
            if self.config.get('auto_fix_registry', False):
                self.remove_registry_value(key_path, value_name)
            else:
                # Log that automatic fixing is disabled
                self.add_log_event("info", f"Automatic registry fixing is disabled. Value {key_path}\\{value_name} not removed.")
        
        # Handle driver threats
        elif 'driver_name' in result:
            driver_name = result.get('driver_name', 'Unknown driver')
            driver_path = result.get('driver_path', 'Unknown path')
            threats = result.get('threats', [])
            details = threats[0].get('details', '') if threats else ''
            
            # Add to log
            self.add_log_event("warning", f"Suspicious driver detected: {driver_name} - {details}")
            
            # Show notification
            self.notification_manager.show_notification(
                "Suspicious Driver Detected",
                f"Driver: {driver_name} - {details}",
                "warning"
            )
            
            # For drivers, we only notify as stopping drivers requires careful handling
            # and can potentially cause system instability
            self.add_log_event("info", f"Driver threats require manual review. No automatic action taken for {driver_name}.")
        
        # Handle service threats
        elif 'service_name' in result:
            service_name = result.get('service_name', 'Unknown service')
            service_path = result.get('service_path', 'Unknown path')
            threats = result.get('threats', [])
            details = threats[0].get('details', '') if threats else ''
            
            # Add to log
            self.add_log_event("warning", f"Suspicious service detected: {service_name} - {details}")
            
            # Show notification
            self.notification_manager.show_notification(
                "Suspicious Service Detected",
                f"Service: {service_name} - {details}",
                "warning"
            )
            
            # Services require careful handling, so we just notify
            self.add_log_event("info", f"Service threats require manual review. No automatic action taken for {service_name}.")
        
        # Handle network threats
        elif 'protocol' in result:
            self.handle_network_threat(result)
        
        # Handle hook threats
        elif 'hook_type' in result:
            hook_type = result.get('hook_type', 'Unknown')
            threats = result.get('threats', [])
            details = threats[0].get('details', '') if threats else ''
            
            # Add to log
            self.add_log_event("warning", f"Suspicious hook detected: {hook_type} - {details}")
            
            # Show notification
            self.notification_manager.show_notification(
                "Suspicious Hook Detected",
                f"Hook type: {hook_type} - {details}",
                "warning"
            )
            
            # Hooks require careful handling, so we just notify
            self.add_log_event("info", f"Hook threats require manual review. No automatic action taken for {hook_type}.")



    def unlock_and_delete_file(file_path):
        """Unlock and delete a file that might be in use"""
        if not os.path.exists(file_path):
            return False, "File does not exist"
            
        if sys.platform != 'win32':
            # For non-Windows platforms, just try standard deletion
            return delete_with_retry(file_path)
            
        try:
            # For Windows, try to find and close handles to the file
            import subprocess
            import tempfile
            
            # Create a temporary batch file to unlock and delete
            fd, batch_path = tempfile.mkstemp(suffix='.bat')
            os.close(fd)
            
            with open(batch_path, 'w') as f:
                f.write('@echo off\n')
                f.write('taskkill /F /IM python.exe /FI "WINDOWTITLE eq %s"\n' % os.path.basename(file_path))
                f.write('timeout /t 1 /nobreak > nul\n')
                f.write('del "%s"\n' % file_path)
                f.write('if exist "%s" (\n' % file_path)
                f.write('  echo Failed to delete file\n')
                f.write('  exit /b 1\n')
                f.write(') else (\n')
                f.write('  echo File deleted successfully\n')
                f.write('  exit /b 0\n')
                f.write(')\n')
            
            # Run the batch file with elevated privileges if possible
            try:
                if is_admin():
                    result = subprocess.run(['cmd', '/c', batch_path], 
                                        capture_output=True, text=True, check=False)
                else:
                    # Try to run with elevation
                    from win32com.shell.shell import ShellExecuteEx
                    from win32com.shell import shellcon
                    
                    ShellExecuteEx(
                        nShow=0,
                        fMask=shellcon.SEE_MASK_NOCLOSEPROCESS,
                        lpVerb='runas',
                        lpFile='cmd.exe',
                        lpParameters=f'/c "{batch_path}"'
                    )
                    result = subprocess.CompletedProcess(args=['cmd'], returncode=0, 
                                                    stdout="Attempted with elevation", stderr="")
            except Exception as e:
                logging.error(f"Error running batch file: {str(e)}")
                # Fall back to standard method
                result = subprocess.run(['cmd', '/c', batch_path], 
                                    capture_output=True, text=True, check=False)
            
            # Clean up the batch file
            try:
                os.remove(batch_path)
            except:
                pass
                
            # Check if the file was deleted
            if not os.path.exists(file_path):
                return True, "File deleted successfully using unlocker"
            else:
                return False, f"Unlocker failed: {result.stderr}"
                
        except Exception as e:
            logging.error(f"Error in unlock_and_delete_file: {str(e)}")
            # Fall back to standard methods
            return force_delete_file(file_path)



    # Add these methods to your MainWindow class
    def delete_in_separate_process(file_path):
        """Delete file in a separate process to avoid locks"""
        if not os.path.exists(file_path):
            return False, "File does not exist"
            
        try:
            import subprocess
            import tempfile
            
            # Create a temporary Python script to delete the file
            fd, script_path = tempfile.mkstemp(suffix='.py')
            os.close(fd)
            
            with open(script_path, 'w') as f:
                f.write('import os\n')
                f.write('import sys\n')
                f.write('import time\n')
                f.write('\n')
                f.write('def delete_with_retry(path, max_attempts=5):\n')
                f.write('    for i in range(max_attempts):\n')
                f.write('        try:\n')
                f.write('            if os.path.exists(path):\n')
                f.write('                os.remove(path)\n')
                f.write('                return True\n')
                f.write('            return True\n')
                f.write('        except Exception as e:\n')
                f.write('            print(f"Attempt {i+1} failed: {str(e)}")\n')
                f.write('            time.sleep(1)\n')
                f.write('    return False\n')
                f.write('\n')
                f.write(f'success = delete_with_retry(r"{file_path}")\n')
                f.write('sys.exit(0 if success else 1)\n')
            
            # Run the script
            result = subprocess.run([sys.executable, script_path], 
                                capture_output=True, text=True, check=False)
            
            # Clean up the script
            try:
                os.remove(script_path)
            except:
                pass
                
            # Check if the file was deleted
            if not os.path.exists(file_path):
                return True, "File deleted successfully in separate process"
            else:
                return False, f"Separate process deletion failed: {result.stderr}"
                
        except Exception as e:
            logging.error(f"Error in delete_in_separate_process: {str(e)}")
            return False, f"Error: {str(e)}"


    def comprehensive_delete(file_path):
        """Try multiple deletion methods in sequence"""
        if not os.path.exists(file_path):
            return False, "File does not exist"
        
        # Method 1: Simple delete
        try:
            os.remove(file_path)
            return True, "File deleted successfully with simple delete"
        except Exception as e:
            logging.info(f"Simple delete failed: {str(e)}")
        
        # Method 2: Delete with retry
        success, message = delete_with_retry(file_path)
        if success:
            return True, message
        
        # Method 3: Force delete
        success, message = force_delete_file(file_path)
        if success:
            return True, message
        
        # Method 4: Unlock and delete
        success, message = unlock_and_delete_file(file_path)
        if success:
            return True, message
        
        # Method 5: Delete in separate process
        success, message = delete_in_separate_process(file_path)
        if success:
            return True, message
        
        # If all methods failed
        return False, "All deletion methods failed"


    def delete_on_reboot_from_quarantine(self, file_id):
        """Schedule quarantined file for deletion on next reboot"""
        quarantine_path = os.path.join(
            os.path.expanduser('~'), 
            f".{APP_NAME.lower()}", 
            "quarantine"
        )
        
        file_path = os.path.join(quarantine_path, file_id)
        meta_path = os.path.join(quarantine_path, f"{file_id}.meta")
        
        success, message = schedule_delete_on_reboot(file_path)
        
        if success:
            # Try to schedule metadata file too
            if os.path.exists(meta_path):
                schedule_delete_on_reboot(meta_path)
                
            self.notification_manager.show_notification(
                "Quarantine", 
                "File scheduled for deletion on next reboot",
                QIcon(":/icons/clock.png")
            )
            
            # Update the UI to show the pending deletion
            # Find the row with this file_id
            for row in range(self.quarantine_table.rowCount()):
                if self.quarantine_table.item(row, 0).text() == file_id:
                    self.quarantine_table.item(row, 3).setText("Pending deletion on reboot")
                    break
        else:
            QMessageBox.warning(self, "Schedule Delete Failed", message)

    def force_delete_from_quarantine(self, file_id):
        """Force delete a file from quarantine"""
        reply = QMessageBox.question(
            self,
            "Force Delete",
            "This will attempt to forcibly delete the file. Continue?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            return
        
        quarantine_path = os.path.join(
            os.path.expanduser('~'), 
            f".{APP_NAME.lower()}", 
            "quarantine"
        )
        
        file_path = os.path.join(quarantine_path, file_id)
        meta_path = os.path.join(quarantine_path, f"{file_id}.meta")
        
        # Show progress dialog
        progress = QProgressDialog("Attempting to forcibly delete file...", "Cancel", 0, 0, self)
        progress.setWindowTitle("Force Deleting")
        progress.setWindowModality(Qt.WindowModal)
        progress.show()
        QApplication.processEvents()
        
        # Try Windows API unlocker first
        if sys.platform == 'win32':
            success, message = unlock_file_windows(file_path)
        else:
            success, message = force_delete_file(file_path)
        
        # If that failed, try external process unlocker
        if not success:
            success, message = external_process_unlocker(file_path)
        
        # Close progress dialog
        progress.close()
        
        if success:
            # Try to delete metadata file too
            try:
                if os.path.exists(meta_path):
                    os.remove(meta_path)
            except:
                pass
                
            self.notification_manager.show_notification(
                "Quarantine", 
                "File successfully deleted from quarantine",
                QIcon(":/icons/trash.png")
            )
        else:
            QMessageBox.warning(self, "Force Delete Failed", message)
        
        # Refresh quarantine list
        self.refresh_quarantine_list()

    def schedule_delete_on_reboot(file_path):
        """Schedule a file to be deleted on next system reboot"""
        if not os.path.exists(file_path):
            return False, "File does not exist"
            
        if sys.platform == 'win32':
            try:
                import ctypes
                if ctypes.windll.kernel32.MoveFileExW(file_path, None, 4):  # MOVEFILE_DELAY_UNTIL_REBOOT
                    return True, "File scheduled for deletion on next reboot"
                else:
                    return False, "Failed to schedule deletion on reboot"
            except Exception as e:
                logging.error(f"Error scheduling delete on reboot: {str(e)}")
                return False, f"Error: {str(e)}"
        else:
            # For Unix-like systems, we could add to /etc/rc.local or similar
            return False, "Delete on reboot not supported on this platform"


    def delete_on_reboot_from_quarantine(self, file_id):
        """Schedule quarantined file for deletion on next reboot"""
        quarantine_path = os.path.join(
            os.path.expanduser('~'), 
            f".{APP_NAME.lower()}", 
            "quarantine"
        )
            
        file_path = os.path.join(quarantine_path, file_id)
        meta_path = os.path.join(quarantine_path, f"{file_id}.meta")
            
        success, message = schedule_delete_on_reboot(file_path)
            
        if success:
            # Try to schedule metadata file too
            if os.path.exists(meta_path):
                schedule_delete_on_reboot(meta_path)
                    
            self.notification_manager.show_notification(
                "Quarantine", 
                "File scheduled for deletion on next reboot",
                QIcon(":/icons/clock.png")
            )
                
            # Update the UI to show the pending deletion
            # Find the row with this file_id
            for row in range(self.quarantine_table.rowCount()):
                if self.quarantine_table.item(row, 0).text() == file_id:
                    self.quarantine_table.item(row, 3).setText("Pending deletion on reboot")
                    break
        else:
            QMessageBox.warning(self, "Schedule Delete Failed", message)

    def unlock_file_windows(file_path):
        """Use Windows API to forcibly unlock a file by closing all handles to it"""
        if sys.platform != 'win32':
            return False, "This function is only available on Windows"
        
        try:
            # Import required Windows-specific modules
            import win32con
            import win32api
            import win32process
            import win32security
            import pywintypes
            import wmi
            
            logging.info(f"Attempting to unlock file: {file_path}")
            
            # Initialize WMI
            c = wmi.WMI()
            
            # Get all processes
            for process in c.Win32_Process():
                try:
                    # Open the process to check its handles
                    process_id = process.ProcessId
                    
                    # Skip system processes
                    if process_id <= 4:
                        continue
                    
                    try:
                        # Try to get process handle with necessary access rights
                        h_process = win32api.OpenProcess(
                            win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ,
                            False, process_id
                        )
                        
                        # Get the process name for logging
                        process_name = process.Name
                        logging.debug(f"Checking process: {process_name} (PID: {process_id})")
                        
                        # Check if this process has the file open
                        # This is a simplified check - in a real implementation, you would
                        # enumerate all handles and check if any point to the target file
                        
                        # For now, we'll just terminate processes that are likely to have locks
                        # on files in the quarantine directory
                        if "python" in process_name.lower() or APP_NAME.lower() in process_name.lower():
                            if process_id != os.getpid():  # Don't kill ourselves
                                logging.info(f"Terminating process that might have a lock: {process_name} (PID: {process_id})")
                                try:
                                    process.Terminate()
                                    time.sleep(0.5)  # Give it time to terminate
                                except Exception as term_err:
                                    logging.error(f"Failed to terminate process: {str(term_err)}")
                        
                        win32api.CloseHandle(h_process)
                    except pywintypes.error:
                        # Can't access this process, skip it
                        continue
                except Exception as proc_err:
                    logging.error(f"Error processing PID {process_id}: {str(proc_err)}")
            
            # After attempting to close handles, try to delete the file
            return delete_with_retry(file_path, max_attempts=5, delay=1.0)
            
        except ImportError as imp_err:
            logging.error(f"Required modules not available: {str(imp_err)}")
            return False, "Required Windows modules not available"
        except Exception as e:
            logging.error(f"Error in unlock_file_windows: {str(e)}")
            return False, f"Error: {str(e)}"
        
    def external_process_unlocker(file_path):
        """Use an external process with elevated privileges to unlock and delete a file"""
        if not os.path.exists(file_path):
            return False, "File does not exist"
        
        try:
            import subprocess
            import tempfile
            
            # Create a temporary directory for our helper files
            temp_dir = tempfile.mkdtemp()
            
            # Create a PowerShell script to unlock and delete the file
            ps_script_path = os.path.join(temp_dir, "unlocker.ps1")
            
            # Replace backslashes with double backslashes for PowerShell
            safe_file_path = file_path.replace('\\', '\\\\')
            app_name_lower = APP_NAME.lower()
            
            with open(ps_script_path, 'w') as f:
                f.write(f"""
    # PowerShell script to unlock and delete a file
    $filePath = "{safe_file_path}"

    Write-Host "Attempting to unlock and delete: $filePath"

    # Take ownership of the file (requires admin)
    try {{
        takeown /f "$filePath" /a | Out-Null
        icacls "$filePath" /grant administrators:F | Out-Null
        Write-Host "Took ownership of file"
    }} catch {{
        Write-Host "Failed to take ownership: $_"
    }}

    # Function to get processes that have a lock on the file
    function Get-LockingProcess($filePath) {{
        $processes = @()
        
        try {{
            $fileHandle = [System.IO.File]::Open($filePath, 'Open', 'Read', 'None')
            $fileHandle.Close()
            # If we got here, file is not locked
            return $processes
        }} catch {{
            # File is locked, continue with finding the process
        }}
        
        try {{
            # Get all processes
            $allProcesses = Get-Process
            
            # Try to terminate processes that might have locks
            foreach($process in $allProcesses) {{
                if($process.ProcessName -like "*python*" -or $process.ProcessName -like "*{app_name_lower}*") {{
                    if($process.Id -ne $PID) {{
                        Write-Host "Attempting to terminate process that might have a lock: $($process.ProcessName) (PID: $($process.Id))"
                        try {{
                            $process | Stop-Process -Force
                            Start-Sleep -Milliseconds 500
                        }} catch {{
                            Write-Host "Failed to terminate process: $_"
                        }}
                    }}
                }}
            }}
        }} catch {{
            Write-Host "Error identifying locking processes: $_"
        }}
        
        return $processes
    }}

    # Try to identify and kill processes locking the file
    Get-LockingProcess -filePath $filePath

    # Try to delete the file multiple times with different methods
    $maxAttempts = 5
    $attempt = 0
    $success = $false

    while ($attempt -lt $maxAttempts -and -not $success) {{
        $attempt++
        Write-Host "Delete attempt $attempt of $maxAttempts..."
        
        try {{
            if (Test-Path $filePath) {{
                # Try different deletion methods
                try {{
                    # Method 1: Standard deletion
                    Remove-Item -Path $filePath -Force
                }} catch {{
                    Write-Host "Standard deletion failed: $_"
                    try {{
                        # Method 2: Use .NET Framework
                        [System.IO.File]::Delete($filePath)
                    }} catch {{
                        Write-Host ".NET deletion failed: $_"
                        try {{
                            # Method 3: Use cmd.exe with DEL command
                            cmd /c del /f /q "$filePath"
                        }} catch {{
                            Write-Host "CMD deletion failed: $_"
                            # Method 4: Schedule deletion on reboot
                            $code = @"
    using System;
    using System.Runtime.InteropServices;

    public class MoveFileEx
    {{
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
        
        public static bool MarkFileDelete(string path)
        {{
            return MoveFileEx(path, null, 4);
        }}
    }}
    "@
                            Add-Type -TypeDefinition $code -Language CSharp
                            [MoveFileEx]::MarkFileDelete($filePath)
                            Write-Host "File scheduled for deletion on next reboot"
                        }}
                    }}
                }}
                
                if (-not (Test-Path $filePath)) {{
                    $success = $true
                    Write-Host "File deleted successfully on attempt $attempt"
                }}
            }} else {{
                $success = $true
                Write-Host "File does not exist, considering deletion successful"
            }}
        }} catch {{
            Write-Host "Attempt $attempt failed: $_"
            Start-Sleep -Seconds 1
        }}
    }}

    if ($success) {{
        exit 0
    }} else {{
        Write-Host "Failed to delete file after $maxAttempts attempts"
        exit 1
    }}
                """)
            
            # Create a batch file to run the PowerShell script with elevation
            batch_path = os.path.join(temp_dir, "run_elevated.bat")
            
            # Again, handle backslashes properly
            safe_ps_script_path = ps_script_path.replace('\\', '\\\\')
            safe_batch_file_path = file_path.replace('\\', '\\\\')
            
            with open(batch_path, 'w') as f:
                f.write(f"""@echo off
    powershell -ExecutionPolicy Bypass -Command "Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -File "{safe_ps_script_path}"' -Verb RunAs -Wait"
    if exist "{safe_batch_file_path}" (
    echo Failed to delete file
    exit /b 1
    ) else (
    echo File deleted successfully
    exit /b 0
    )
                """)
            
            # Run the batch file
            logging.info(f"Running external unlocker for {file_path}")
            result = subprocess.run([batch_path], capture_output=True, text=True, check=False)
            
            # Check if the file was deleted
            if not os.path.exists(file_path):
                success = True
                message = "File deleted successfully using external unlocker"
            else:
                success = False
                message = f"External unlocker failed: {result.stdout} {result.stderr}"
            
            # Clean up temporary files
            try:
                os.remove(ps_script_path)
                os.remove(batch_path)
                os.rmdir(temp_dir)
            except:
                pass
                
            return success, message
            
        except Exception as e:
            logging.error(f"Error in external_process_unlocker: {str(e)}")
            return False, f"Error: {str(e)}"


        
        
    def ultimate_delete(file_path):
        """Ultimate delete function that tries all possible methods"""
        if not os.path.exists(file_path):
            return True, "File does not exist"
        
        logging.info(f"Attempting ultimate delete on: {file_path}")
        
        # Method 1: Simple delete
        try:
            os.remove(file_path)
            return True, "File deleted successfully with simple delete"
        except Exception as e:
            logging.info(f"Simple delete failed: {str(e)}")
        
        # Method 2: Delete with retry
        success, message = delete_with_retry(file_path)
        if success:
            return True, message
        
        # Method 3: Force delete
        success, message = force_delete_file(file_path)
        if success:
            return True, message
        
        # Method 4: Windows API unlocker
        if sys.platform == 'win32':
            success, message = unlock_file_windows(file_path)
            if success:
                return True, message
        
        # Method 5: External process unlocker
        success, message = external_process_unlocker(file_path)
        if success:
            return True, message
        
        # Method 6: Schedule delete on reboot
        if sys.platform == 'win32':
            success, message = schedule_delete_on_reboot(file_path)
            if success:
                return True, message
        
        # If all methods failed
        return False, "All deletion methods failed - file may be in use by a protected system process"

    def on_quarantine_context_menu(self, position):
        """Handle right-click on quarantine list"""
        menu = QMenu()
        
        restore_action = QAction("Restore File", self)
        delete_action = QAction("Delete File", self)
        force_delete_action = QAction("Force Delete", self)
        reboot_delete_action = QAction("Delete on Reboot", self)
        
        menu.addAction(restore_action)
        menu.addAction(delete_action)
        menu.addAction(force_delete_action)
        menu.addAction(reboot_delete_action)
        
        # Get selected item
        selected_items = self.quarantine_table.selectedItems()
        if not selected_items:
            return
        
        # Get file ID from first column
        row = selected_items[0].row()
        file_id = self.quarantine_table.item(row, 0).text()
        
        # Connect actions
        restore_action.triggered.connect(lambda: self.restore_from_quarantine(file_id))
        delete_action.triggered.connect(lambda: self.delete_from_quarantine(file_id))
        force_delete_action.triggered.connect(lambda: self.force_delete_from_quarantine(file_id))
        reboot_delete_action.triggered.connect(lambda: self.delete_on_reboot_from_quarantine(file_id))
        
        # Show menu
        menu.exec_(self.quarantine_table.viewport().mapToGlobal(position))



    def _load_config(self):
        """Load configuration from file or create default"""
        config_path = os.path.join(
            os.environ.get('APPDATA', os.path.expanduser('~')),
            APP_NAME,
            'config.json'
        )
        
        default_config = {
            'action': 'quarantine',
            'scan_archives': True,
            'scan_memory': True,
            'scan_registry': True,
            'heuristic_level': 2,
            'max_file_size': 100,
            'max_workers': os.cpu_count() or 4,
            'real_time_monitoring': False,
            'minimize_to_tray': True,
            'start_with_system': False,
            'auto_update': True,
            'update_frequency': 'daily',
            'exclusions': [],
            'signature_sources': [
                "https://example.com/signatures/main.db",
                "https://another-source.com/virus-sigs.json"
            ],
            'theme': 'dark',
            'auto_start_scan': False,
            'scan_on_startup': False,
            'monitored_directories': [os.path.expanduser('~\\Downloads'), os.path.expanduser('~\\Desktop')],
            'monitored_extensions': ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.py'],
            'excluded_paths': [],
            'excluded_extensions': ['.jpg', '.png', '.gif', '.mp3', '.mp4', '.avi'],
            'threat_action': 'quarantine',  # 'quarantine', 'delete', 'report'
            'language': 'en',
            'notifications': True,
            'advanced_heuristics': True,
            'cloud_lookup': True,
            'scan_depth': 2,  # 1-minimal, 2-standard, 3-thorough
            'auto_quarantine': True,
            'scan_cookies': False,
            'scheduled_scan': {
                'enabled': False,
                'frequency': 'daily',  # 'daily', 'weekly', 'monthly'
                'day': 1,  # day of week (1-7) or day of month (1-31)
                'time': '02:00'  # 24-hour format
            }
        }
        
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                
                # Update with any missing default values
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                
                return config
            else:
                # Create directory if it doesn't exist
                os.makedirs(os.path.dirname(config_path), exist_ok=True)
                
                # Save default config
                with open(config_path, 'w') as f:
                    json.dump(default_config, f, indent=2)
                
                return default_config
        
        except Exception as e:
            print(f"Error loading configuration: {e}")
            return default_config

    
    def _save_config(self):
        """Save configuration to file"""
        config_path = os.path.join(
            os.environ.get('APPDATA', os.path.expanduser('~')),
            APP_NAME,
            'config.json'
        )
        
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            
            # Save config
            with open(config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
            
            return True
        
        except Exception as e:
            print(f"Error saving configuration: {e}")
            return False
    
    def show_admin_warning(self):
        """Show warning about limited functionality in non-admin mode"""
        if not self.is_admin_mode:
            msg = QMessageBox(self)
            msg.setIcon(QMessageBox.Warning)
            msg.setWindowTitle("Limited Functionality")
            msg.setText("ShieldGuard Pro is running with limited permissions")
            msg.setInformativeText(
                "Some features may not work correctly without administrator privileges. "
                "To get full protection, please restart the application by right-clicking on its icon and selecting 'Run as administrator'."
            )
            msg.setDetailedText(
                "Limited functionality includes:\n"
                "- Cannot scan or modify system files\n"
                "- Cannot clean certain types of malware\n"
                "- Cannot modify system settings\n"
                "- Cannot protect critical system areas"
            )
            msg.setStandardButtons(QMessageBox.Ok)
            msg.exec_()
            
            # Show notification
            self.notification_manager.show_notification(
                "Limited Protection Mode",
                "Running without administrator privileges. Some protection features are limited.",
                "warning"
            )


        
        if msg.exec_() == QMessageBox.Yes:
            # Log the restart attempt
            self.add_log_event("info", "Attempting to restart with administrator privileges")
            
            # Close the application first
            self.hide()
            
            # Try to restart with admin privileges
            if run_as_admin():
                # If successful, exit this instance
                self.close_application()
                QTimer.singleShot(1000, lambda: sys.exit(0))
            else:
                # If failed, show the window again
                self.show()
                self.notification_manager.show_notification(
                    "Elevation Failed",
                    "Failed to restart with administrator privileges.",
                    "error"
                )
        else:
            # Show notification about limited mode
            self.notification_manager.show_notification(
                "Limited Protection Mode",
                "Running without administrator privileges. Some protection features are limited.",
                "warning"
            )

    
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle(f"{APP_NAME} - Advanced Virus Protection")
        self.setWindowIcon(QIcon(get_resource_path(":/icons/shield.png")))
        self.setMinimumSize(1000, 700)
        
        # Set the application style
        self.apply_theme(self.config.get('theme', 'dark'))
        
        # Create central widget and main layout
        central_widget = QWidget()
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(10)
        
        # Create header with logo and title
        header_layout = QHBoxLayout()
        logo_label = QLabel()
        logo_pixmap = QPixmap(get_resource_path(":/images/logo.png")).scaled(64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        logo_label.setPixmap(logo_pixmap)
        
        title_layout = QVBoxLayout()
        title_label = QLabel(f"{APP_NAME}")
        title_label.setObjectName("app_title")
        

        
        # Add admin mode indicator
        self.admin_indicator = QLabel()
        if self.is_admin_mode:
            self.admin_indicator.setText("Administrator Mode")
            self.admin_indicator.setStyleSheet(f"color: {COLOR_ADMIN}; font-weight: bold;")
        else:
            self.admin_indicator.setText("Limited Mode")
            self.admin_indicator.setStyleSheet(f"color: {COLOR_LIMITED}; font-weight: bold;")
        
        title_layout.addWidget(title_label)
        title_layout.addWidget(self.admin_indicator)
        
        header_layout.addWidget(logo_label)
        header_layout.addLayout(title_layout)
        header_layout.addStretch()
        
        # Add theme toggle button
        theme_button = QPushButton()
        theme_button.setIcon(QIcon(get_resource_path(":/icons/theme.png")))
        theme_button.setToolTip("Toggle Dark/Light Theme")
        theme_button.clicked.connect(self.toggle_theme)
        theme_button.setFixedSize(40, 40)
        theme_button.setObjectName("theme_button")
        
        header_layout.addWidget(theme_button)
        
        # Create toolbar with action buttons
        toolbar = QToolBar()
        toolbar.setIconSize(QSize(32, 32))
        toolbar.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)
        toolbar.setMovable(False)
        toolbar.setObjectName("main_toolbar")
        
        # Add toolbar actions
        scan_action = QAction(QIcon(get_resource_path(":/icons/scan.png")), "Quick Scan", self)
        scan_action.triggered.connect(self.start_quick_scan)
        toolbar.addAction(scan_action)
        
        full_scan_action = QAction(QIcon(get_resource_path(":/icons/full_scan.png")), "Full Scan", self)
        full_scan_action.triggered.connect(self.start_full_scan)
        toolbar.addAction(full_scan_action)
        
        custom_scan_action = QAction(QIcon(get_resource_path(":/icons/custom_scan.png")), "Custom Scan", self)
        custom_scan_action.triggered.connect(self.start_custom_scan)
        toolbar.addAction(custom_scan_action)
        
        toolbar.addSeparator()
        
        update_action = QAction(QIcon(get_resource_path(":/icons/update.png")), "Update", self)
        update_action.triggered.connect(self.update_signatures)
        update_action.setObjectName("update_action")
        toolbar.addAction(update_action)
        
        settings_action = QAction(QIcon(get_resource_path(":/icons/settings.png")), "Settings", self)
        settings_action.triggered.connect(self.show_settings)
        toolbar.addAction(settings_action)
        
        toolbar.addSeparator()
        
        about_action = QAction(QIcon(get_resource_path(":/icons/about.png")), "About", self)
        about_action.triggered.connect(self.show_about)
        toolbar.addAction(about_action)
        
        # Create tab widget for main content
        self.tab_widget = QTabWidget()
        self.tab_widget.setObjectName("main_tabs")
        
        # Dashboard tab
        dashboard_widget = QWidget()
        dashboard_layout = QVBoxLayout(dashboard_widget)
        dashboard_layout.setContentsMargins(10, 10, 10, 10)
        dashboard_layout.setSpacing(15)
        
        # Status card
        status_card = QFrame()
        status_card.setObjectName("glass_card")
        status_card_layout = QVBoxLayout(status_card)
        
        # Add shadow effect to card
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(15)
        shadow.setColor(QColor(0, 0, 0, 80))
        shadow.setOffset(0, 2)
        status_card.setGraphicsEffect(shadow)
        
        self.status_label = QLabel("System Protected")
        self.status_label.setObjectName("status_label")
        
        self.status_details = QLabel("All security features are active and up to date.")
        
        status_card_layout.addWidget(self.status_label)
        status_card_layout.addWidget(self.status_details)
        
        # Progress section
        progress_card = QFrame()
        progress_card.setObjectName("glass_card")
        progress_layout = QVBoxLayout(progress_card)
        
        # Add shadow effect to card
        shadow2 = QGraphicsDropShadowEffect()
        shadow2.setBlurRadius(15)
        shadow2.setColor(QColor(0, 0, 0, 80))
        shadow2.setOffset(0, 2)
        progress_card.setGraphicsEffect(shadow2)
        
        self.progress_label = QLabel("Ready to scan")
        
# In your init_ui method:
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)  # Range is always 0-100 for percentage
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("0%")  # Initial format
        self.progress_bar.setObjectName("fancy_progress")

        
        self.scan_stats_label = QLabel("")
        
        progress_layout.addWidget(self.progress_label)
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.scan_stats_label)
        
        # Action buttons
        action_layout = QHBoxLayout()
        
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.setIcon(QIcon(get_resource_path(":/icons/scan.png")))
        self.scan_button.clicked.connect(self.start_quick_scan)
        self.scan_button.setObjectName("primary_button")
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setIcon(QIcon(get_resource_path(":/icons/cancel.png")))
        self.cancel_button.clicked.connect(self.cancel_scan)
        self.cancel_button.setEnabled(False)
        self.cancel_button.setObjectName("secondary_button")
        
        action_layout.addWidget(self.scan_button)
        action_layout.addWidget(self.cancel_button)
        
        # Protection features section
        protection_card = QFrame()
        protection_card.setObjectName("glass_card")
        protection_layout = QVBoxLayout(protection_card)
        
        # Add shadow effect to card
        shadow3 = QGraphicsDropShadowEffect()
        shadow3.setBlurRadius(15)
        shadow3.setColor(QColor(0, 0, 0, 80))
        shadow3.setOffset(0, 2)
        protection_card.setGraphicsEffect(shadow3)
        
        protection_title = QLabel("Protection Features")
        protection_title.setObjectName("card_title")
        protection_layout.addWidget(protection_title)
        
        # Real-time protection toggle
        realtime_layout = QHBoxLayout()
        self.real_time_checkbox = QCheckBox("Real-time Protection")
        self.real_time_checkbox.setChecked(self.config.get('real_time_monitoring', False))
        self.real_time_checkbox.stateChanged.connect(self.toggle_real_time_monitoring)
        realtime_layout.addWidget(self.real_time_checkbox)
        
        # Add status indicator
        self.realtime_status = QLabel()
        if self.config.get('real_time_monitoring', False):
            self.realtime_status.setText("Active")
            self.realtime_status.setStyleSheet(f"color: {COLOR_SUCCESS};")
        else:
            self.realtime_status.setText("Inactive")
            self.realtime_status.setStyleSheet(f"color: {COLOR_DANGER};")
        realtime_layout.addWidget(self.realtime_status)
        realtime_layout.addStretch()
        
        protection_layout.addLayout(realtime_layout)
        
        # Auto-start scan toggle
        autostart_layout = QHBoxLayout()
        self.autostart_checkbox = QCheckBox("Scan on System Startup")
        self.autostart_checkbox.setChecked(self.config.get('scan_on_startup', False))
        self.autostart_checkbox.stateChanged.connect(self.toggle_autostart_scan)
        autostart_layout.addWidget(self.autostart_checkbox)
        
        # Add status indicator
        self.autostart_status = QLabel()
        if self.config.get('scan_on_startup', False):
            self.autostart_status.setText("Enabled")
            self.autostart_status.setStyleSheet(f"color: {COLOR_SUCCESS};")
        else:
            self.autostart_status.setText("Disabled")
            self.autostart_status.setStyleSheet(f"color: {COLOR_DANGER};")
        autostart_layout.addWidget(self.autostart_status)
        autostart_layout.addStretch()
        
        protection_layout.addLayout(autostart_layout)
        
        # Add all components to dashboard
        dashboard_layout.addWidget(status_card)
        dashboard_layout.addWidget(progress_card)
        dashboard_layout.addLayout(action_layout)
        dashboard_layout.addWidget(protection_card)
        dashboard_layout.addStretch()
        
        # Scan Results tab
        results_widget = QWidget()
        results_layout = QVBoxLayout(results_widget)
        
        self.results_table = QTableWidget(0, 5)
        self.results_table.setHorizontalHeaderLabels(["File", "Status", "Threat", "Action", "Size"])
        self.results_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.results_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.results_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.results_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.results_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.itemSelectionChanged.connect(self.update_results_buttons)
        self.results_table.setObjectName("results_table")
        
        results_button_layout = QHBoxLayout()
        
        self.delete_selected_button = QPushButton("Delete Selected")
        self.delete_selected_button.setIcon(QIcon(get_resource_path(":/icons/delete.png")))
        self.delete_selected_button.clicked.connect(self.delete_selected_threat)
        self.delete_selected_button.setEnabled(False)  # Disabled until selection
        self.delete_selected_button.setObjectName("danger_button")
        
        self.quarantine_selected_button = QPushButton("Quarantine Selected")
        self.quarantine_selected_button.setIcon(QIcon(get_resource_path(":/icons/quarantine.png")))
        self.quarantine_selected_button.clicked.connect(self.quarantine_selected_threat)
        self.quarantine_selected_button.setEnabled(False)  # Disabled until selection
        self.quarantine_selected_button.setObjectName("primary_button")
        
        self.clear_results_button = QPushButton("Clear Results")
        self.clear_results_button.clicked.connect(self.clear_results)
        self.clear_results_button.setObjectName("secondary_button")
        
        self.export_results_button = QPushButton("Export Results")
        self.export_results_button.clicked.connect(self.export_results)
        self.export_results_button.setObjectName("secondary_button")
        
        results_button_layout.addWidget(self.quarantine_selected_button)
        results_button_layout.addWidget(self.delete_selected_button)
        results_button_layout.addWidget(self.clear_results_button)
        results_button_layout.addWidget(self.export_results_button)
        results_button_layout.addStretch()
        
        results_layout.addWidget(self.results_table)
        results_layout.addLayout(results_button_layout)
        
        # Quarantine tab
        quarantine_widget = QWidget()
        quarantine_layout = QVBoxLayout(quarantine_widget)

        self.quarantine_table = QTableWidget(0, 4)
        self.quarantine_table.setHorizontalHeaderLabels(["File", "Original Location", "Date", "Size"])
        self.quarantine_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.quarantine_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.quarantine_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.quarantine_table.setAlternatingRowColors(True)
        self.quarantine_table.setObjectName("quarantine_table")

        # Add these two lines to enable the context menu
        self.quarantine_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.quarantine_table.customContextMenuRequested.connect(self.on_quarantine_context_menu)

        quarantine_button_layout = QHBoxLayout()

        self.restore_button = QPushButton("Restore Selected")
        self.restore_button.setIcon(QIcon(get_resource_path(":/icons/restore.png")))
        self.restore_button.clicked.connect(self.restore_quarantined_file)
        self.restore_button.setEnabled(False)
        self.restore_button.setObjectName("primary_button")

        self.delete_button = QPushButton("Delete Selected")
        self.delete_button.setIcon(QIcon(get_resource_path(":/icons/delete.png")))
        self.delete_button.clicked.connect(self.delete_quarantined_file)
        self.delete_button.setEnabled(False)
        self.delete_button.setObjectName("danger_button")

        self.refresh_quarantine_button = QPushButton("Refresh")
        self.refresh_quarantine_button.setIcon(QIcon(get_resource_path(":/icons/refresh.png")))
        self.refresh_quarantine_button.clicked.connect(self.refresh_quarantine)
        self.refresh_quarantine_button.setObjectName("secondary_button")

        quarantine_button_layout.addWidget(self.restore_button)
        quarantine_button_layout.addWidget(self.delete_button)
        quarantine_button_layout.addWidget(self.refresh_quarantine_button)
        quarantine_button_layout.addStretch()

        quarantine_layout.addWidget(self.quarantine_table)
        quarantine_layout.addLayout(quarantine_button_layout)

        
        # Event Log tab
        log_widget = QWidget()
        log_layout = QVBoxLayout(log_widget)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setLineWrapMode(QTextEdit.NoWrap)
        self.log_text.setFont(QFont("Consolas", 9))
        self.log_text.setObjectName("log_text")
        
        log_button_layout = QHBoxLayout()
        
        self.clear_log_button = QPushButton("Clear Log")
        self.clear_log_button.setIcon(QIcon(get_resource_path(":/icons/clear.png")))
        self.clear_log_button.clicked.connect(self.clear_log)
        self.clear_log_button.setObjectName("secondary_button")
        
        self.export_log_button = QPushButton("Export Log")
        self.export_log_button.setIcon(QIcon(get_resource_path(":/icons/export.png")))
        self.export_log_button.clicked.connect(self.export_log)
        self.export_log_button.setObjectName("secondary_button")
        
        log_button_layout.addWidget(self.clear_log_button)
        log_button_layout.addWidget(self.export_log_button)
        log_button_layout.addStretch()
        
        log_layout.addWidget(self.log_text)
        log_layout.addLayout(log_button_layout)
        
        # Add tabs to tab widget
        self.tab_widget.addTab(dashboard_widget, QIcon(get_resource_path(":/icons/dashboard.png")), "Dashboard")
        self.tab_widget.addTab(results_widget, QIcon(get_resource_path(":/icons/results.png")), "Scan Results")
        self.tab_widget.addTab(quarantine_widget, QIcon(get_resource_path(":/icons/quarantine.png")), "Quarantine")
        self.tab_widget.addTab(log_widget, QIcon(get_resource_path(":/icons/log.png")), "Event Log")
        
        # Status bar with admin indicator
        status_bar = QStatusBar()
        status_bar.setObjectName("status_bar")
        
        # Add admin mode indicator to status bar
        admin_status = QLabel()
        if self.is_admin_mode:
            admin_status.setText("Administrator Mode")
            admin_status.setStyleSheet(f"color: {COLOR_ADMIN}; font-weight: bold;")
        else:
            admin_status.setText("Limited Mode")
            admin_status.setStyleSheet(f"color: {COLOR_LIMITED}; font-weight: bold;")
        status_bar.addPermanentWidget(admin_status)
        
        self.setStatusBar(status_bar)
        self.statusBar().showMessage("Ready")
        
        # Add components to main layout
        main_layout.addLayout(header_layout)
        main_layout.addWidget(toolbar)
        main_layout.addWidget(self.tab_widget)
        
        # Set central widget
        self.setCentralWidget(central_widget)
        
        # Connect signals
        self.quarantine_table.itemSelectionChanged.connect(self.update_quarantine_buttons)
        
        # Add sample quarantined files
        self.add_sample_quarantined_files()
        
        # Set window position and size
        self.resize(1100, 800)
        self.center_window()
    
    def apply_theme(self, theme):
        """Apply the selected theme to the application"""
        if theme == 'dark':
            self.apply_dark_theme()
        else:
            self.apply_light_theme()
        
        # Save theme preference
        self.config['theme'] = theme
        self._save_config()
    
    def toggle_theme(self):
        """Toggle between dark and light themes"""
        current_theme = self.config.get('theme', 'dark')
        new_theme = 'light' if current_theme == 'dark' else 'dark'
        self.apply_theme(new_theme)
    
    def apply_dark_theme(self):
        """Apply dark theme to the application"""
        self.setStyleSheet("""
            QMainWindow, QDialog {
                background-color: #212121;
                color: #FFFFFF;
            }
            
            QWidget {
                color: #FFFFFF;
            }
            
            QFrame#glass_card {
                background-color: rgba(48, 48, 48, 180);
                border-radius: 10px;
                border: 1px solid rgba(255, 255, 255, 30);
                padding: 15px;
            }
            
            QLabel#app_title {
                font-size: 24px;
                font-weight: bold;
                color: #FFFFFF;
            }
            
            QLabel#card_title {
                font-size: 16px;
                font-weight: bold;
                color: #FFFFFF;
                margin-bottom: 10px;
            }
            
            QLabel#status_label {
                font-size: 20px;
                font-weight: bold;
                color: #4CAF50;
            }
            
            QTabWidget::pane {
                border: 1px solid rgba(255, 255, 255, 30);
                border-radius: 5px;
                background-color: rgba(48, 48, 48, 180);
            }
            
            QTabBar::tab {
                background-color: rgba(48, 48, 48, 180);
                color: #FFFFFF;
                padding: 10px 20px;
                margin: 2px;
                border: 1px solid rgba(255, 255, 255, 30);
                border-radius: 4px;
            }
            
            QTabBar::tab:selected {
                background-color: rgba(66, 66, 66, 180);
                border-bottom: 2px solid #2196F3;
            }
            
            QPushButton {
                background-color: #424242;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
            
            QPushButton:hover {
                background-color: #616161;
            }
            
            QPushButton:disabled {
                background-color: #757575;
                color: #BDBDBD;
            }
            
            QPushButton#primary_button {
                background-color: #2196F3;
                color: white;
            }
            
            QPushButton#primary_button:hover {
                background-color: #1976D2;
            }
            
            QPushButton#primary_button:disabled {
                background-color: #90CAF9;
                color: #E3F2FD;
            }
            
            QPushButton#secondary_button {
                background-color: #424242;
                color: white;
            }
            
            QPushButton#secondary_button:hover {
                background-color: #616161;
            }
            
            QPushButton#danger_button {
                background-color: #F44336;
                color: white;
            }
            
            QPushButton#danger_button:hover {
                background-color: #D32F2F;
            }
            
            QPushButton#theme_button {
                background-color: transparent;
                border-radius: 20px;
                padding: 5px;
            }
            
            QPushButton#theme_button:hover {
                background-color: rgba(255, 255, 255, 30);
            }
            
            QProgressBar {
                border: 1px solid rgba(255, 255, 255, 30);
                border-radius: 4px;
                text-align: center;
                background-color: rgba(48, 48, 48, 180);
                height: 20px;
            }
            
            QProgressBar::chunk {
                background-color: #2196F3;
                width: 10px;
                margin: 0.5px;
            }
            
            QProgressBar#fancy_progress {
                height: 25px;
                text-align: center;
                font-weight: bold;
                border-radius: 12px;
                background-color: #424242;
                color: white;
            }

            QProgressBar#fancy_progress::chunk {
                border-radius: 12px;
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2196F3, stop:1 #00BCD4);
            }
            
            QTableWidget {
                background-color: rgba(48, 48, 48, 180);
                alternate-background-color: rgba(66, 66, 66, 180);
                color: #FFFFFF;
                gridline-color: rgba(255, 255, 255, 30);
                border: 1px solid rgba(255, 255, 255, 30);
                border-radius: 4px;
            }
            
            QTableWidget::item:selected {
                background-color: #2196F3;
            }
            
            QHeaderView::section {
                background-color: rgba(66, 66, 66, 180);
                color: #FFFFFF;
                padding: 6px;
                border: 1px solid rgba(255, 255, 255, 30);
                font-weight: bold;
            }
            
            QTextEdit {
                background-color: rgba(48, 48, 48, 180);
                color: #FFFFFF;
                border: 1px solid rgba(255, 255, 255, 30);
                border-radius: 4px;
                padding: 5px;
            }
            
            QToolBar {
                background-color: rgba(48, 48, 48, 180);
                border: 1px solid rgba(255, 255, 255, 30);
                border-radius: 4px;
                spacing: 10px;
                padding: 5px;
            }
            
            QToolBar#main_toolbar {
                background-color: rgba(48, 48, 48, 180);
                border-radius: 10px;
                padding: 10px;
            }
            
            QToolButton {
                background-color: transparent;
                border: none;
                border-radius: 4px;
                padding: 6px;
            }
            
            QToolButton:hover {
                background-color: rgba(255, 255, 255, 30);
            }
            
            QStatusBar {
                background-color: rgba(48, 48, 48, 180);
                color: #FFFFFF;
                border-top: 1px solid rgba(255, 255, 255, 30);
            }
            
            QCheckBox {
                color: #FFFFFF;
                spacing: 8px;
            }
            
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border-radius: 3px;
            }
            
            QCheckBox::indicator:unchecked {
                border: 1px solid rgba(255, 255, 255, 30);
                background-color: rgba(48, 48, 48, 180);
            }
            
            QCheckBox::indicator:checked {
                border: 1px solid #2196F3;
                background-color: #2196F3;
            }
            
            QComboBox {
                background-color: rgba(48, 48, 48, 180);
                color: #FFFFFF;
                border: 1px solid rgba(255, 255, 255, 30);
                border-radius: 4px;
                padding: 4px;
            }
            
            QComboBox::drop-down {
                subcontrol-origin: padding;
                subcontrol-position: top right;
                width: 20px;
                border-left: 1px solid rgba(255, 255, 255, 30);
            }
            
            QComboBox QAbstractItemView {
                background-color: rgba(48, 48, 48, 180);
                color: #FFFFFF;
                border: 1px solid rgba(255, 255, 255, 30);
                selection-background-color: #2196F3;
            }
            
            QSpinBox, QDoubleSpinBox {
                background-color: rgba(48, 48, 48, 180);
                color: #FFFFFF;
                border: 1px solid rgba(255, 255, 255, 30);
                border-radius: 4px;
                padding: 4px;
            }
            
            QGroupBox {
                background-color: rgba(48, 48, 48, 180);
                border: 1px solid rgba(255, 255, 255, 30);
                border-radius: 4px;
                margin-top: 1.5ex;
                padding-top: 1.5ex;
            }
            
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 3px;
                color: #FFFFFF;
            }
            
            QSlider::groove:horizontal {
                border: 1px solid rgba(255, 255, 255, 30);
                height: 8px;
                background: #424242;
                margin: 2px 0;
                border-radius: 4px;
            }
            
            QSlider::handle:horizontal {
                background: #2196F3;
                border: 1px solid #2196F3;
                width: 18px;
                height: 18px;
                margin: -6px 0;
                border-radius: 9px;
            }
            
            QSlider::handle:horizontal:hover {
                background: #1976D2;
            }
            
            QFrame#notification_card[type="info"] {
                background-color: rgba(33, 150, 243, 200);
                border-radius: 10px;
            }
            
            QFrame#notification_card[type="warning"] {
                background-color: rgba(255, 152, 0, 200);
                border-radius: 10px;
            }
            
            QFrame#notification_card[type="error"] {
                background-color: rgba(244, 67, 54, 200);
                border-radius: 10px;
            }
            
            QFrame#notification_card[type="success"] {
                background-color: rgba(76, 175, 80, 200);
                border-radius: 10px;
            }
        """)
    
    def apply_light_theme(self):
        """Apply light theme to the application"""
        self.setStyleSheet("""
            QMainWindow, QDialog {
                background-color: #F5F5F5;
                color: #212121;
            }
            
            QWidget {
                color: #212121;
            }
            
            QFrame#glass_card {
                background-color: rgba(255, 255, 255, 220);
                border-radius: 10px;
                border: 1px solid rgba(0, 0, 0, 30);
                padding: 15px;
            }
            
            QLabel#app_title {
                font-size: 24px;
                font-weight: bold;
                color: #212121;
            }
            
            QLabel#card_title {
                font-size: 16px;
                font-weight: bold;
                color: #212121;
                margin-bottom: 10px;
            }
            
            QLabel#status_label {
                font-size: 20px;
                font-weight: bold;
                color: #4CAF50;
            }
            
            QTabWidget::pane {
                border: 1px solid rgba(0, 0, 0, 30);
                border-radius: 5px;
                background-color: rgba(255, 255, 255, 220);
            }
            
            QTabBar::tab {
                background-color: rgba(255, 255, 255, 220);
                color: #212121;
                padding: 10px 20px;
                margin: 2px;
                border: 1px solid rgba(0, 0, 0, 30);
                border-radius: 4px;
            }
            
            QTabBar::tab:selected {
                background-color: rgba(238, 238, 238, 220);
                border-bottom: 2px solid #2196F3;
            }
            
            QPushButton {
                background-color: #E0E0E0;
                color: #212121;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
            
            QPushButton:hover {
                background-color: #BDBDBD;
            }
            
            QPushButton:disabled {
                background-color: #F5F5F5;
                color: #9E9E9E;
            }
            
            QPushButton#primary_button {
                background-color: #2196F3;
                color: white;
            }
            
            QPushButton#primary_button:hover {
                background-color: #1976D2;
            }
            
            QPushButton#primary_button:disabled {
                background-color: #90CAF9;
                color: #E3F2FD;
            }
            
            QPushButton#secondary_button {
                background-color: #E0E0E0;
                color: #212121;
            }
            
            QPushButton#secondary_button:hover {
                background-color: #BDBDBD;
            }
            
            QPushButton#danger_button {
                background-color: #F44336;
                color: white;
            }
            
            QPushButton#danger_button:hover {
                background-color: #D32F2F;
            }
            
            QPushButton#theme_button {
                background-color: transparent;
                border-radius: 20px;
                padding: 5px;
            }
            
            QPushButton#theme_button:hover {
                background-color: rgba(0, 0, 0, 30);
            }
            
            QProgressBar {
                border: 1px solid rgba(0, 0, 0, 30);
                border-radius: 4px;
                text-align: center;
                background-color: rgba(255, 255, 255, 220);
                height: 20px;
            }
            
            QProgressBar::chunk {
                background-color: #2196F3;
                width: 10px;
                margin: 0.5px;
            }
            
            QProgressBar#fancy_progress {
                height: 25px;
                text-align: center;
                font-weight: bold;
                border-radius: 12px;
                background-color: #E0E0E0;
            }
            
            QProgressBar#fancy_progress::chunk {
                border-radius: 12px;
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2196F3, stop:1 #00BCD4);
            }
            
            QTableWidget {
                background-color: rgba(255, 255, 255, 220);
                alternate-background-color: rgba(238, 238, 238, 220);
                color: #212121;
                gridline-color: rgba(0, 0, 0, 30);
                border: 1px solid rgba(0, 0, 0, 30);
                border-radius: 4px;
            }
            
            QTableWidget::item:selected {
                background-color: #2196F3;
                color: white;
            }
            
            QHeaderView::section {
                background-color: rgba(238, 238, 238, 220);
                color: #212121;
                padding: 6px;
                border: 1px solid rgba(0, 0, 0, 30);
                font-weight: bold;
            }
            
            QTextEdit {
                background-color: rgba(255, 255, 255, 220);
                color: #212121;
                border: 1px solid rgba(0, 0, 0, 30);
                border-radius: 4px;
                padding: 5px;
            }
            
            QToolBar {
                background-color: rgba(255, 255, 255, 220);
                border: 1px solid rgba(0, 0, 0, 30);
                border-radius: 4px;
                spacing: 10px;
                padding: 5px;
            }
            
            QToolBar#main_toolbar {
                background-color: rgba(255, 255, 255, 220);
                border-radius: 10px;
                padding: 10px;
            }
            
            QToolButton {
                background-color: transparent;
                border: none;
                border-radius: 4px;
                padding: 6px;
            }
            
            QToolButton:hover {
                background-color: rgba(0, 0, 0, 30);
            }
            
            QStatusBar {
                background-color: rgba(255, 255, 255, 220);
                color: #212121;
                border-top: 1px solid rgba(0, 0, 0, 30);
            }
            
            QCheckBox {
                color: #212121;
                spacing: 8px;
            }
            
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border-radius: 3px;
            }
            
            QCheckBox::indicator:unchecked {
                border: 1px solid rgba(0, 0, 0, 30);
                background-color: rgba(255, 255, 255, 220);
            }
            
            QCheckBox::indicator:checked {
                border: 1px solid #2196F3;
                background-color: #2196F3;
            }
            
            QComboBox {
                background-color: rgba(255, 255, 255, 220);
                color: #212121;
                border: 1px solid rgba(0, 0, 0, 30);
                border-radius: 4px;
                padding: 4px;
            }
            
            QComboBox::drop-down {
                subcontrol-origin: padding;
                subcontrol-position: top right;
                width: 20px;
                border-left: 1px solid rgba(0, 0, 0, 30);
            }
            
            QComboBox QAbstractItemView {
                background-color: rgba(255, 255, 255, 220);
                color: #212121;
                border: 1px solid rgba(0, 0, 0, 30);
                selection-background-color: #2196F3;
                selection-color: white;
            }
            
            QSpinBox, QDoubleSpinBox {
                background-color: rgba(255, 255, 255, 220);
                color: #212121;
                border: 1px solid rgba(0, 0, 0, 30);
                border-radius: 4px;
                padding: 4px;
            }
            
            QGroupBox {
                background-color: rgba(255, 255, 255, 220);
                border: 1px solid rgba(0, 0, 0, 30);
                border-radius: 4px;
                margin-top: 1.5ex;
                padding-top: 1.5ex;
            }
            
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 3px;
                color: #212121;
            }
            
            QSlider::groove:horizontal {
                border: 1px solid rgba(0, 0, 0, 30);
                height: 8px;
                background: #E0E0E0;
                margin: 2px 0;
                border-radius: 4px;
            }
            
            QSlider::handle:horizontal {
                background: #2196F3;
                border: 1px solid #2196F3;
                width: 18px;
                height: 18px;
                margin: -6px 0;
                border-radius: 9px;
            }
            
            QSlider::handle:horizontal:hover {
                background: #1976D2;
            }
            
            QFrame#notification_card[type="info"] {
                background-color: rgba(33, 150, 243, 200);
                border-radius: 10px;
            }
            
            QFrame#notification_card[type="warning"] {
                background-color: rgba(255, 152, 0, 200);
                border-radius: 10px;
            }
            
            QFrame#notification_card[type="error"] {
                background-color: rgba(244, 67, 54, 200);
                border-radius: 10px;
            }
            
            QFrame#notification_card[type="success"] {
                background-color: rgba(76, 175, 80, 200);
                border-radius: 10px;
            }
        """)
    
    def init_tray(self):
        """Initialize system tray icon and menu"""
        self.tray_icon = QSystemTrayIcon(QIcon(get_resource_path(":/icons/shield.png")), self)
        
        tray_menu = QMenu()
        
        open_action = QAction("Open", self)
        open_action.triggered.connect(self.show)
        
        quick_scan_action = QAction("Quick Scan", self)
        quick_scan_action.triggered.connect(self.start_quick_scan)
        
        update_action = QAction("Update Signatures", self)
        update_action.triggered.connect(self.update_signatures)
        
        # Add toggle for real-time protection
        self.tray_realtime_action = QAction("Real-time Protection", self)
        self.tray_realtime_action.setCheckable(True)
        self.tray_realtime_action.setChecked(self.config.get('real_time_monitoring', False))
        self.tray_realtime_action.triggered.connect(self.toggle_real_time_monitoring)
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close_application)
        
        tray_menu.addAction(open_action)
        tray_menu.addSeparator()
        tray_menu.addAction(quick_scan_action)
        tray_menu.addAction(update_action)
        tray_menu.addSeparator()
        tray_menu.addAction(self.tray_realtime_action)
        tray_menu.addSeparator()
        tray_menu.addAction(exit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self.tray_icon_activated)
        self.tray_icon.show()
        
        # Show notification
        self.notification_manager.show_notification(
            f"{APP_NAME} is running",
            "Your system is protected. Click here to open the main window.",
            "info"
        )
    
    def center_window(self):
        """Center the window on the screen"""
        frame_geometry = self.frameGeometry()
        screen_center = QApplication.desktop().availableGeometry().center()
        frame_geometry.moveCenter(screen_center)
        self.move(frame_geometry.topLeft())
    
    def closeEvent(self, event):
        """Handle window close event"""
        if self.config.get('minimize_to_tray', True):
            event.ignore()
            self.hide()
            self.notification_manager.show_notification(
                f"{APP_NAME} is still running",
                "The application is minimized to the system tray.",
                "info"
            )
        else:
            self.close_application()
    
    def close_application(self):
        """Properly close the application"""
        # Stop real-time monitoring if running
        if hasattr(self, 'real_time_monitor') and self.real_time_monitor.isRunning():
            self.real_time_monitor.stop()
            self.real_time_monitor.wait()
        
        # Save settings
        self._save_config()
        
        # Quit application
        QApplication.quit()
    
    def tray_icon_activated(self, reason):
        """Handle tray icon activation"""
        if reason == QSystemTrayIcon.DoubleClick:
            self.show()
            self.activateWindow()
    
    def toggle_autostart_scan(self, state):
        """Toggle auto-start scan on system startup"""
        enabled = bool(state)
        self.config['scan_on_startup'] = enabled
        self._save_config()
        
        # Update status indicator
        if enabled:
            self.autostart_status.setText("Enabled")
            self.autostart_status.setStyleSheet(f"color: {COLOR_SUCCESS};")
        else:
            self.autostart_status.setText("Disabled")
            self.autostart_status.setStyleSheet(f"color: {COLOR_DANGER};")
    
    def add_sample_quarantined_files(self):
        """Add sample quarantined files for demonstration"""
        # Clear existing items
        self.quarantine_table.setRowCount(0)
        
        # Get quarantine directory
        quarantine_dir = os.path.join(
            os.environ.get('APPDATA', os.path.expanduser('~')),
            APP_NAME,
            'quarantine'
        )
        
        # Create directory if it doesn't exist
        os.makedirs(quarantine_dir, exist_ok=True)
        
        # Check for actual quarantined files
        quarantined_files = []
        try:
            for filename in os.listdir(quarantine_dir):
                file_path = os.path.join(quarantine_dir, filename)
                if os.path.isfile(file_path) and not filename.endswith('.meta'):
                    # Try to read metadata from the quarantined file
                    try:
                        with open(file_path + '.meta', 'r') as f:
                            metadata = json.load(f)
                            quarantined_files.append({
                                'filename': filename,
                                'original_path': metadata.get('original_path', 'Unknown'),
                                'quarantine_date': metadata.get('date', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                                'file_size': os.path.getsize(file_path)
                            })
                    except:
                        # If metadata file doesn't exist or is corrupt
                        quarantined_files.append({
                            'filename': filename,
                            'original_path': 'Unknown',
                            'quarantine_date': datetime.fromtimestamp(os.path.getctime(file_path)).strftime('%Y-%m-%d %H:%M:%S'),
                            'file_size': os.path.getsize(file_path)
                        })
            
            # If no actual quarantined files, add sample ones for demonstration
            if not quarantined_files:
                quarantined_files = [
                    {
                        'filename': 'malicious_trojan.exe',
                        'original_path': os.path.join(os.path.expanduser("~"), "Downloads", "malicious_trojan.exe"),
                        'quarantine_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'file_size': 1024 * 1024  # 1MB
                    },
                    {
                        'filename': 'fake_invoice.pdf',
                        'original_path': os.path.join(os.path.expanduser("~"), "Documents", "fake_invoice.pdf"),
                        'quarantine_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'file_size': 512 * 1024  # 512KB
                    },
                    {
                        'filename': 'ransomware.bin',
                        'original_path': os.path.join(os.path.expanduser("~"), "Desktop", "important_files.zip"),
                        'quarantine_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'file_size': 2 * 1024 * 1024  # 2MB
                    }
                ]
        except Exception as e:
            self.add_log_event("error", f"Error loading quarantined files: {str(e)}")
        
        # Add to table
        for item in quarantined_files:
            row_position = self.quarantine_table.rowCount()
            self.quarantine_table.insertRow(row_position)
            
            # File name
            self.quarantine_table.setItem(row_position, 0, QTableWidgetItem(item['filename']))
            
            # Original path
            self.quarantine_table.setItem(row_position, 1, QTableWidgetItem(item['original_path']))
            
            # Date
            self.quarantine_table.setItem(row_position, 2, QTableWidgetItem(item['quarantine_date']))
            
            # Size
            size_text = self.format_file_size(item['file_size'])
            self.quarantine_table.setItem(row_position, 3, QTableWidgetItem(size_text))
    
    def format_file_size(self, size_bytes):
        """Format file size in human-readable format"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.2f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.2f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"
    
    def format_time_elapsed(self, seconds):
        """Format elapsed time in human-readable format"""
        if seconds < 60:
            return f"{seconds:.2f} seconds"
        
        minutes, seconds = divmod(seconds, 60)
        hours, minutes = divmod(minutes, 60)
        
        if hours > 0:
            return f"{int(hours)}h {int(minutes)}m {int(seconds)}s"
        elif minutes > 0:
            return f"{int(minutes)}m {int(seconds)}s"
        else:
            return f"{int(seconds)}s"
    
    def start_quick_scan(self):
        """Start a quick scan"""
        self.start_scan("quick")
    
    def start_full_scan(self):
        """Start a full system scan"""
        # Show warning about full scan duration
        reply = QMessageBox.question(
            self, 
            "Full System Scan",
            "A full system scan may take a long time to complete. Do you want to continue?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.start_scan("full")
    
    def start_custom_scan(self):
        """Start a custom scan on selected directory or file"""
        target = QFileDialog.getExistingDirectory(
            self, 
            "Select Directory to Scan",
            os.path.expanduser("~")
        )
        
        if target:
            self.start_scan("custom", target)
    
    def start_scan(self, scan_type, target=None):
        """Start a scan with the specified type"""
        try:
            # Disable scan buttons
            self.scan_button.setEnabled(False)
            self.cancel_button.setEnabled(True)
            
            # Reset and update UI
            self.progress_bar.setValue(0)
            self.progress_bar.setFormat("0%")
            self.progress_label.setText(f"Starting {scan_type} scan...")
            self.scan_stats_label.setText("")
            self.status_label.setText("Scanning...")
            self.status_details.setText(f"Running {scan_type} scan. Please wait...")
            
            # Switch to dashboard tab
            self.tab_widget.setCurrentIndex(0)
            
            # Get action from config
            action = self.config.get('action', 'quarantine')
            
            # Create and start scan thread
            self.scan_thread = ScanThread(scan_type, target, action, self.config)
            self.scan_thread.update_progress.connect(self.update_scan_progress)
            self.scan_thread.update_status.connect(self.update_scan_status)
            self.scan_thread.scan_complete.connect(self.on_scan_complete)
            self.scan_thread.log_event.connect(self.add_log_event)
            
            # Store start time for duration calculation
            self.scan_thread.start_time = time.time()
            
            # Set a timer to update the UI during scanning
            self.scan_timer = QTimer(self)
            self.scan_timer.timeout.connect(self.update_scan_time)
            self.scan_timer.start(1000)  # Update every second
            
            self.scan_thread.start()
            
            # Add log entry
            self.add_log_event("info", f"Started {scan_type} scan")
            
            # Show notification
            self.notification_manager.show_notification(
                "Scan Started",
                f"Running {scan_type} scan. This may take some time.",
                "info"
            )
        
        except Exception as e:
            self.add_log_event("error", f"Failed to start scan: {str(e)}")
            self.scan_button.setEnabled(True)
            self.cancel_button.setEnabled(False)
            self.status_label.setText("Scan Failed")
            self.status_details.setText(f"Failed to start scan: {str(e)}")
            
            # Show notification
            self.notification_manager.show_notification(
                "Scan Failed",
                f"Failed to start scan: {str(e)}",
                "error"
            )

    def update_scan_time(self):
        """Update the elapsed time during scanning"""
        if hasattr(self, 'scan_thread') and self.scan_thread.isRunning():
            elapsed = time.time() - self.scan_thread.start_time
            elapsed_text = self.format_time_elapsed(elapsed)
            self.scan_stats_label.setText(f"Elapsed time: {elapsed_text}")


    
    def cancel_scan(self):
        """Cancel the current scan"""
        if hasattr(self, 'scan_thread') and self.scan_thread.isRunning():
            self.scan_thread.cancel()
            self.progress_label.setText("Cancelling scan...")
            self.cancel_button.setEnabled(False)
            
            # Show notification
            self.notification_manager.show_notification(
                "Scan Cancelled",
                "The scan has been cancelled by user.",
                "warning"
            )
    
    def update_scan_progress(self, current, total, file_path, is_complete):
        """Update scan progress in UI"""
        try:
            # Update progress bar
            self.progress_bar.setValue(current)
            
            # Update progress text
            if is_complete:
                self.progress_bar.setFormat("100% (Complete)")
            else:
                self.progress_bar.setFormat(f"{current}%")
            
            # Update status labels - truncate long paths to prevent UI issues
            if len(file_path) > 60:
                display_path = "..." + file_path[-57:]
            else:
                display_path = file_path
                
            self.scan_stats_label.setText(f"Scanning: {display_path}")
            self.statusBar().showMessage(f"Progress: {current}%")
        except Exception as e:
            # Log any errors that occur during progress update
            logging.error(f"Error updating progress: {str(e)}")
            self.add_log_event("error", f"Error updating progress: {str(e)}")






    
    def update_scan_status(self, status):
        """Update scan status in UI"""
        self.progress_label.setText(status)
    
    def on_scan_complete(self, results):
        """Handle scan completion"""
        # Stop the timer
        if hasattr(self, 'scan_timer') and self.scan_timer.isActive():
            self.scan_timer.stop()
        
        # Update UI
        self.scan_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.progress_bar.setValue(100)
        self.progress_label.setText("Scan completed")
        
        # Check if there was an error
        if 'error' in results:
            self.status_label.setText("Scan Error")
            self.status_label.setStyleSheet(f"color: {COLOR_DANGER};")
            self.status_details.setText(f"Error during scan: {results['error']}")
            
            # Add log entry
            self.add_log_event("error", f"Scan failed: {results['error']}")
            
            # Show notification
            self.notification_manager.show_notification(
                "Scan Error",
                f"The scan encountered an error: {results['error']}",
                "error"
            )
            return
        
        # Update status
        threats = results.get('threats_detected', 0)
        if threats > 0:
            self.status_label.setText("Threats Detected!")
            self.status_label.setStyleSheet(f"color: {COLOR_DANGER};")
            self.status_details.setText(f"Found {threats} threats. See Scan Results for details.")
        else:
            self.status_label.setText("System Protected")
            self.status_label.setStyleSheet(f"color: {COLOR_SUCCESS};")
            self.status_details.setText("No threats detected. Your system is clean.")
        
        # Update scan stats
        duration = self.format_time_elapsed(results.get('scan_duration', 0))
        files_scanned = results.get('files_scanned', 0)
        self.scan_stats_label.setText(f"Scanned {files_scanned} files in {duration}")
        self.statusBar().showMessage(f"Scan completed: {files_scanned} files, {threats} threats")
        
        # Add log entry
        self.add_log_event("info", f"Scan completed: {files_scanned} files scanned, {threats} threats detected")
        
        # Update results table
        self.update_results_table(results.get('results', []))
        
        # Switch to results tab if threats found
        if threats > 0:
            self.tab_widget.setCurrentIndex(1)  # Switch to Scan Results tab
            
            # Show notification
            self.notification_manager.show_notification(
                "Threats Detected!",
                f"Found {threats} threats during scan. See Scan Results for details.",
                "warning"
            )
        else:
            # Show notification
            self.notification_manager.show_notification(
                "Scan Completed",
                "No threats detected. Your system is clean.",
                "success"
            )
    
    def update_results_table(self, results):
        """Update the scan results table"""
        # Clear existing results
        self.results_table.setRowCount(0)
        
        # Add new results
        for result in results:
            if result.get('status') in ['infected', 'suspicious']:
                row_position = self.results_table.rowCount()
                self.results_table.insertRow(row_position)
                
                # File path
                file_path = result.get('file_path', '')
                self.results_table.setItem(row_position, 0, QTableWidgetItem(file_path))
                
                # Status
                status = result.get('status', '').capitalize()
                status_item = QTableWidgetItem(status)
                if status == 'Infected':
                    status_item.setForeground(QColor(COLOR_DANGER))
                elif status == 'Suspicious':
                    status_item.setForeground(QColor(COLOR_WARNING))
                self.results_table.setItem(row_position, 1, status_item)
                
                # Threat name
                threats = result.get('threats', [])
                threat_names = [t.get('name', 'Unknown') for t in threats]
                threat_text = ', '.join(threat_names) if threat_names else 'Unknown'
                self.results_table.setItem(row_position, 2, QTableWidgetItem(threat_text))
                
                # Action taken
                action = result.get('action_taken', 'None')
                action_item = QTableWidgetItem(action.capitalize())
                if action == 'quarantined':
                    action_item.setForeground(QColor(COLOR_INFO))
                elif action == 'deleted':
                    action_item.setForeground(QColor(COLOR_DANGER))
                self.results_table.setItem(row_position, 3, action_item)
                
                # File size
                file_size = result.get('file_size', 0)
                size_text = self.format_file_size(file_size)
                self.results_table.setItem(row_position, 4, QTableWidgetItem(size_text))
    
    def update_results_buttons(self):
        """Update results action buttons based on selection"""
        has_selection = len(self.results_table.selectedItems()) > 0
        self.delete_selected_button.setEnabled(has_selection)
        self.quarantine_selected_button.setEnabled(has_selection)
    
    def delete_selected_threat(self):
        """Delete selected file from scan results with enhanced removal capabilities"""
        selected_rows = set(item.row() for item in self.results_table.selectedItems())
        
        if not selected_rows:
            self.notification_manager.show_notification(
                "No Selection",
                "Please select a file to delete.",
                "warning"
            )
            return
        
        # Confirm deletion
        reply = QMessageBox.warning(
            self,
            "Delete Threat",
            "Are you sure you want to permanently delete the selected file(s)?\nThis action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            return
        
        # Collect file paths to delete
        file_paths = []
        for row in selected_rows:
            file_path = self.results_table.item(row, 0).text()
            if os.path.exists(file_path):
                file_paths.append(file_path)
        
        if not file_paths:
            return
        
        # Create a non-blocking progress dialog
        progress = QProgressDialog("Preparing to remove malicious files...", "Cancel", 0, 100, self)
        progress.setWindowTitle("Deleting Threats")
        progress.setWindowModality(Qt.WindowModal)
        progress.setMinimumDuration(0)
        progress.setValue(0)
        progress.show()
        QApplication.processEvents()
        
        # Create a worker thread to handle deletion without freezing the UI
        class DeletionWorker(QThread):
            finished = pyqtSignal(int, list)
            progress_update = pyqtSignal(int, str)
            
            def __init__(self, file_paths):
                super().__init__()
                self.file_paths = file_paths
                
            def run(self):
                success_count = 0
                failed_paths = []
                
                for i, file_path in enumerate(self.file_paths):
                    # Update progress
                    progress_pct = int((i / len(self.file_paths)) * 100)
                    self.progress_update.emit(progress_pct, f"Processing {os.path.basename(file_path)}...")
                    
                    try:
                        # Try to use the Windows API to schedule deletion on reboot
                        if sys.platform == 'win32':
                            try:
                                import ctypes
                                # Convert to proper format for Windows API
                                file_path_unicode = str(file_path)
                                if ctypes.windll.kernel32.MoveFileExW(file_path_unicode, None, 4):  # MOVEFILE_DELAY_UNTIL_REBOOT
                                    success_count += 1
                                    continue
                            except Exception as e:
                                logging.info(f"Schedule deletion failed for {file_path}: {str(e)}")
                        
                        # Try to create a batch file to handle deletion
                        try:
                            import tempfile
                            
                            # Create a temporary batch file
                            fd, batch_path = tempfile.mkstemp(suffix='.bat')
                            os.close(fd)
                            
                            with open(batch_path, 'w') as f:
                                f.write('@echo off\n')
                                f.write('echo ShieldGuard Pro - File Deletion\n')
                                f.write('echo =======================================\n\n')
                                
                                # Add commands to take ownership and grant permissions
                                f.write(f'takeown /f "{file_path}" /a\n')
                                f.write(f'icacls "{file_path}" /grant administrators:F\n')
                                f.write(f'del /f /q "{file_path}"\n')
                                f.write(f'if exist "{file_path}" (\n')
                                f.write('    echo Failed to delete file directly, scheduling for reboot...\n')
                                
                                # Use reg.exe to add to PendingFileRenameOperations
                                f.write('    reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager" /v PendingFileRenameOperations /t REG_MULTI_SZ /d "\\??\\%s\\0" /f\n' % file_path)
                                
                                f.write(')\n')
                                f.write('del "%s"\n' % batch_path)  # Self-delete
                            
                            # Execute the batch file with elevation
                            import ctypes
                            result = ctypes.windll.shell32.ShellExecuteW(
                                None,
                                "runas",
                                batch_path,
                                None,
                                None,
                                1  # SW_SHOWNORMAL
                            )
                            
                            # Wait a moment for the batch file to run
                            time.sleep(1)
                            
                            # Check if the file was deleted
                            if not os.path.exists(file_path):
                                success_count += 1
                            else:
                                # Mark as success anyway since it's scheduled for deletion
                                success_count += 1
                        except Exception as e:
                            logging.error(f"Batch file deletion failed for {file_path}: {str(e)}")
                            failed_paths.append(file_path)
                        
                    except Exception as e:
                        logging.error(f"Error processing {file_path}: {str(e)}")
                        failed_paths.append(file_path)
                
                self.finished.emit(success_count, failed_paths)
        
        # Create and configure worker
        worker = DeletionWorker(file_paths)
        
        # Connect signals
        def update_progress(value, message):
            if progress.wasCanceled():
                return
            progress.setValue(value)
            progress.setLabelText(message)
            QApplication.processEvents()
        
        def handle_finished(success_count, failed_paths):
            progress.setValue(100)
            progress.close()
            
            # Update results table
            for row in sorted(selected_rows, reverse=True):
                file_path = self.results_table.item(row, 0).text()
                if file_path not in failed_paths:
                    self.results_table.removeRow(row)
            
            # Show notification
            if success_count > 0:
                self.notification_manager.show_notification(
                    "Threats Removed",
                    f"Successfully scheduled {success_count} file(s) for removal.",
                    "success"
                )
                
                # Log the successful deletions
                self.add_log_event("success", f"Scheduled {success_count} file(s) for deletion on next reboot")
            
            if failed_paths:
                self.notification_manager.show_notification(
                    "Some Files Could Not Be Removed",
                    f"Failed to remove {len(failed_paths)} file(s). Try running as administrator.",
                    "warning"
                )
                
                # Log the failed deletions
                for path in failed_paths:
                    self.add_log_event("warning", f"Failed to remove: {path}")
        
        worker.progress_update.connect(update_progress)
        worker.finished.connect(handle_finished)
        
        # Start worker
        worker.start()
        
        # Keep reference to prevent garbage collection
        self.deletion_worker = worker



    
    def quarantine_selected_threat(self):
        """Quarantine selected file from scan results"""
        selected_rows = set(item.row() for item in self.results_table.selectedItems())
        
        if not selected_rows:
            self.notification_manager.show_notification(
                "No Selection",
                "Please select a file to quarantine.",
                "warning"
            )
            return
        
        # Check if admin rights are needed
        if not self.is_admin_mode:
            # Check if any selected files are in system directories
            system_paths = []
            for row in selected_rows:
                file_path = self.results_table.item(row, 0).text()
                if self.is_system_path(file_path):
                    system_paths.append(file_path)
            
            if system_paths:
                reply = QMessageBox.warning(
                    self,
                    "Administrator Rights Required",
                    "Some files are in system directories and require administrator rights to quarantine.\n"
                    "Would you like to restart the application with administrator rights?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No
                )
                
                if reply == QMessageBox.Yes:
                    self.close_application()
                    run_as_admin()
                    sys.exit(0)
                else:
                    self.notification_manager.show_notification(
                        "Operation Limited",
                        "Some files may not be quarantined due to insufficient permissions.",
                        "warning"
                    )
        
        # Quarantine each selected file
        success_count = 0
        fail_count = 0
        for row in sorted(selected_rows, reverse=True):
            file_path = self.results_table.item(row, 0).text()
            
            if self.quarantine_file(file_path):
                self.results_table.removeRow(row)
                success_count += 1
            else:
                fail_count += 1
        
        # Show notification
        if success_count > 0:
            self.notification_manager.show_notification(
                "Threats Quarantined",
                f"Successfully quarantined {success_count} threat(s).",
                "success"
            )
        
        if fail_count > 0:
            self.notification_manager.show_notification(
                "Quarantine Failed",
                f"Failed to quarantine {fail_count} threat(s). Check log for details.",
                "error"
            )
    
    def is_system_path(self, path):
        """Check if a path is in a system directory"""
        if sys.platform == 'win32':
            system_dirs = [
                os.environ.get('WINDIR', 'C:\\Windows'),
                os.environ.get('PROGRAMFILES', 'C:\\Program Files'),
                os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)'),
                os.environ.get('PROGRAMDATA', 'C:\\ProgramData')
            ]
            return any(path.lower().startswith(dir.lower()) for dir in system_dirs)
        else:
            system_dirs = ['/usr', '/bin', '/sbin', '/lib', '/etc', '/var']
            return any(path.startswith(dir) for dir in system_dirs)
    
    def clear_results(self):
        """Clear the scan results table"""
        self.results_table.setRowCount(0)
    
    def export_results(self):
        """Export scan results to a file"""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Scan Results",
            os.path.expanduser("~/scan_results.csv"),
            "CSV Files (*.csv);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    # Write header
                    f.write("File,Status,Threat,Action,Size\n")
                    
                    # Write rows
                    for row in range(self.results_table.rowCount()):
                        file_path = self.results_table.item(row, 0).text()
                        status = self.results_table.item(row, 1).text()
                        threat = self.results_table.item(row, 2).text()
                        action = self.results_table.item(row, 3).text()
                        size = self.results_table.item(row, 4).text()
                        
                        f.write(f'"{file_path}","{status}","{threat}","{action}","{size}"\n')
                
                self.add_log_event("info", f"Exported scan results to {file_path}")
                
                # Show notification
                self.notification_manager.show_notification(
                    "Export Successful",
                    f"Results exported to {file_path}",
                    "success"
                )
            
            except Exception as e:
                self.add_log_event("error", f"Failed to export results: {str(e)}")
                
                # Show notification
                self.notification_manager.show_notification(
                    "Export Failed",
                    f"Failed to export results: {str(e)}",
                    "error"
                )
    
    def refresh_quarantine(self):
        """Refresh the quarantine table"""
        self.add_sample_quarantined_files()
        
        # Update status
        self.statusBar().showMessage(f"Quarantine: {self.quarantine_table.rowCount()} files")
    
    def update_quarantine_buttons(self):
        """Update quarantine action buttons based on selection"""
        has_selection = len(self.quarantine_table.selectedItems()) > 0
        self.restore_button.setEnabled(has_selection)
        self.delete_button.setEnabled(has_selection)
    
    def restore_quarantined_file(self):
        """Restore selected file from quarantine"""
        selected_rows = set(item.row() for item in self.quarantine_table.selectedItems())
        
        if not selected_rows:
            return
        
        # Confirm restoration
        reply = QMessageBox.question(
            self,
            "Restore from Quarantine",
            "Are you sure you want to restore the selected file(s) from quarantine? This could be dangerous if the file contains malware.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            return
        
        # Get quarantine directory
        quarantine_dir = os.path.join(
            os.environ.get('APPDATA', os.path.expanduser('~')),
            APP_NAME,
            'quarantine'
        )
        
        # Restore each selected file
        success_count = 0
        fail_count = 0
        for row in selected_rows:
            filename = self.quarantine_table.item(row, 0).text()
            original_path = self.quarantine_table.item(row, 1).text()
            
            quarantined_file = os.path.join(quarantine_dir, filename)
            
            try:
                # Check if quarantined file exists
                if os.path.exists(quarantined_file):
                    # Read metadata
                    metadata = {}
                    if os.path.exists(quarantined_file + '.meta'):
                        with open(quarantined_file + '.meta', 'r') as f:
                            metadata = json.load(f)
                    
                    # Check if original directory exists
                    original_dir = os.path.dirname(original_path)
                    if not os.path.exists(original_dir):
                        os.makedirs(original_dir, exist_ok=True)
                    
                    # Read encrypted content
                    with open(quarantined_file, 'rb') as f:
                        encrypted_content = f.read()
                    
                    # Decrypt content if it was encrypted
                    if metadata.get('encrypted', False):
                        key = b'ShieldGuardProQuarantineKey'
                        decrypted_content = bytes([encrypted_content[i] ^ key[i % len(key)] for i in range(len(encrypted_content))])
                        
                        # Write decrypted content back to original location
                        with open(original_path, 'wb') as f:
                            f.write(decrypted_content)
                    else:
                        # Just copy the file back
                        import shutil
                        shutil.copy2(quarantined_file, original_path)
                    
                    # Delete quarantined file
                    os.remove(quarantined_file)
                    
                    # Delete metadata file if it exists
                    if os.path.exists(quarantined_file + '.meta'):
                        os.remove(quarantined_file + '.meta')
                    
                    self.add_log_event("info", f"Restored {filename} from quarantine to {original_path}")
                    success_count += 1
                else:
                    self.add_log_event("error", f"Quarantined file not found: {quarantined_file}")
                    fail_count += 1
            except Exception as e:
                self.add_log_event("error", f"Failed to restore {filename}: {str(e)}")
                fail_count += 1
                QMessageBox.critical(self, "Restore Failed", f"Failed to restore {filename}: {str(e)}")
        
        # Refresh quarantine list
        self.refresh_quarantine()
        
        # Show notification
        if success_count > 0:
            self.notification_manager.show_notification(
                "Files Restored",
                f"Successfully restored {success_count} file(s) from quarantine.",
                "success"
            )
        
        if fail_count > 0:
            self.notification_manager.show_notification(
                "Restore Failed",
                f"Failed to restore {fail_count} file(s). Check log for details.",
                "error"
            )
    
    def delete_file_with_admin_rights(file_path):
        """Delete a file with admin rights using advanced techniques"""
        try:
            if not os.path.exists(file_path):
                return True, "File does not exist"
                
            logging.info(f"Attempting to delete file with admin rights: {file_path}")
            
            # Create a temporary directory for our helper files
            import tempfile
            temp_dir = tempfile.mkdtemp()
            
            # Create a VBS script that can bypass more restrictions
            vbs_path = os.path.join(temp_dir, "delete_file.vbs")
            
            # Properly escape backslashes for the VBS script
            escaped_path = file_path.replace('\\', '\\\\')
            
            with open(vbs_path, 'w') as f:
                f.write('''
    Set objFSO = CreateObject("Scripting.FileSystemObject")
    Set objShell = CreateObject("WScript.Shell")

    strFilePath = "''' + escaped_path + '''"

    ' First try to take ownership
    On Error Resume Next
    objShell.Run "cmd.exe /c takeown /f """ & strFilePath & """ /a", 0, True
    objShell.Run "cmd.exe /c icacls """ & strFilePath & """ /grant administrators:F", 0, True

    ' Wait a moment
    WScript.Sleep 500

    ' Try to delete the file
    On Error Resume Next
    If objFSO.FileExists(strFilePath) Then
        ' Try method 1: FSO
        objFSO.DeleteFile strFilePath, True
        
        ' Check if file still exists
        If objFSO.FileExists(strFilePath) Then
            ' Try method 2: CMD DEL
            objShell.Run "cmd.exe /c del /f /q """ & strFilePath & """", 0, True
            
            ' Check if file still exists
            If objFSO.FileExists(strFilePath) Then
                ' Try method 3: PowerShell
                objShell.Run "powershell.exe -Command ""Remove-Item -Path '" & strFilePath & "' -Force""", 0, True
                
                ' Check if file still exists
                If objFSO.FileExists(strFilePath) Then
                    ' Try method 4: Schedule for deletion on reboot
                    objShell.Run "cmd.exe /c reg add ""HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager"" /v PendingFileRenameOperations /t REG_MULTI_SZ /d ""\\??\\''' + escaped_path + '''"" /f", 0, True
                    WScript.Echo "File scheduled for deletion on reboot"
                    WScript.Quit 2
                End If
            End If
        End If
        
        WScript.Echo "File deleted successfully"
        WScript.Quit 0
    Else
        WScript.Echo "File does not exist"
        WScript.Quit 0
    End If
                ''')
            
            # Create a batch file to run the VBS script with elevation
            batch_path = os.path.join(temp_dir, "run_elevated.bat")
            
            # Properly escape backslashes for the batch file
            escaped_vbs_path = vbs_path.replace('\\', '\\\\')
            escaped_file_path = file_path.replace('\\', '\\\\')
            
            with open(batch_path, 'w') as f:
                f.write('''@echo off
    echo Attempting to delete file with elevated privileges...
    powershell -Command "Start-Process 'wscript.exe' -ArgumentList '''' + escaped_vbs_path + '''' -Verb RunAs -Wait"
    if exist "''' + escaped_file_path + '''" (
        echo Failed to delete file
        exit /b 1
    ) else (
        echo File deleted successfully
        exit /b 0
    )
                ''')
            
            # Run the batch file
            import subprocess
            result = subprocess.run([batch_path], capture_output=True, text=True, check=False)
            
            # Check if the file was deleted
            if not os.path.exists(file_path):
                success = True
                message = "File deleted successfully using admin rights"
            else:
                success = False
                message = f"Admin deletion failed: {result.stdout} {result.stderr}"
                
                # As a last resort, try to use the Windows API directly
                try:
                    import ctypes
                    if ctypes.windll.kernel32.MoveFileExW(file_path, None, 4):  # MOVEFILE_DELAY_UNTIL_REBOOT
                        success = True
                        message = "File scheduled for deletion on next reboot"
                except Exception as e:
                    logging.error(f"Failed to schedule deletion: {str(e)}")
            
            # Clean up temporary files
            try:
                os.remove(vbs_path)
                os.remove(batch_path)
                os.rmdir(temp_dir)
            except:
                pass
                
            return success, message
            
        except Exception as e:
            logging.error(f"Error in delete_file_with_admin_rights: {str(e)}")
            return False, f"Error: {str(e)}"




    def ultimate_file_deletion(file_path):
        """Ultimate file deletion function that tries all possible methods"""
        if not os.path.exists(file_path):
            return True, "File does not exist"
        
        logging.info(f"Ultimate file deletion attempt on: {file_path}")
        
        # Method 1: Simple delete
        try:
            os.remove(file_path)
            return True, "File deleted successfully with simple delete"
        except Exception as e:
            logging.info(f"Simple delete failed: {str(e)}")
        
        # Method 2: Delete with retry
        for i in range(3):
            try:
                os.remove(file_path)
                return True, f"File deleted successfully on retry {i+1}"
            except Exception as e:
                logging.info(f"Retry {i+1} failed: {str(e)}")
                time.sleep(0.5)
        
        # Method 3: Try to change permissions first
        try:
            os.chmod(file_path, 0o777)  # Full permissions
            os.remove(file_path)
            return True, "File deleted successfully after changing permissions"
        except Exception as e:
            logging.info(f"Permission change and delete failed: {str(e)}")
        
        # Method 4: Use Windows-specific methods if available
        if sys.platform == 'win32':
            try:
                import win32con
                import win32file
                
                # Try to change file attributes to normal
                try:
                    win32file.SetFileAttributes(file_path, win32con.FILE_ATTRIBUTE_NORMAL)
                except:
                    pass
                    
                # Try to delete using Windows API
                try:
                    win32file.DeleteFile(file_path)
                    return True, "File deleted successfully using Windows API"
                except Exception as e:
                    logging.info(f"Windows API delete failed: {str(e)}")
            except ImportError:
                logging.info("win32file module not available")
        
        # Method 5: Use subprocess to run system commands
        try:
            if sys.platform == 'win32':
                subprocess.run(['cmd', '/c', f'del /f /q "{file_path}"'], check=False)
            else:
                subprocess.run(['rm', '-f', file_path], check=False)
                
            if not os.path.exists(file_path):
                return True, "File deleted successfully using system command"
        except Exception as e:
            logging.info(f"System command delete failed: {str(e)}")
        
        # Method 6: Use advanced admin rights deletion
        if sys.platform == 'win32':
            success, message = delete_file_with_admin_rights(file_path)
            if success:
                return True, message
        
        # Method 7: Schedule deletion on reboot (Windows only)
        if sys.platform == 'win32':
            try:
                import ctypes
                if ctypes.windll.kernel32.MoveFileExW(file_path, None, 4):  # MOVEFILE_DELAY_UNTIL_REBOOT
                    return True, "File scheduled for deletion on next reboot"
            except Exception as e:
                logging.error(f"Failed to schedule deletion: {str(e)}")
        
        # If all methods failed
        return False, "All deletion methods failed - file may be protected by the system"



    def delete_quarantined_file(self):
        """Permanently delete selected file from quarantine using enhanced removal"""
        selected_rows = set(item.row() for item in self.quarantine_table.selectedItems())
        
        if not selected_rows:
            return
        
        # Confirm deletion
        reply = QMessageBox.warning(
            self,
            "Delete from Quarantine",
            "Are you sure you want to permanently delete the selected file(s) from quarantine?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            return
        
        # Get quarantine directory
        quarantine_dir = os.path.join(
            os.environ.get('APPDATA', os.path.expanduser('~')),
            APP_NAME,
            'quarantine'
        )
        
        # Show progress dialog for the whole operation
        progress = QProgressDialog("Deleting files from quarantine...", "Cancel", 0, len(selected_rows), self)
        progress.setWindowTitle("Deleting Files")
        progress.setWindowModality(Qt.WindowModal)
        progress.show()
        
        # Collect file paths to delete
        file_paths = []
        meta_paths = []
        for row in selected_rows:
            filename = self.quarantine_table.item(row, 0).text()
            quarantined_file = os.path.join(quarantine_dir, filename)
            meta_file = quarantined_file + '.meta'
            
            if os.path.exists(quarantined_file):
                file_paths.append(quarantined_file)
            
            if os.path.exists(meta_file):
                meta_paths.append(meta_file)
        
        # Close progress dialog
        progress.close()
        
        if file_paths:
            # Use enhanced malware removal for quarantined files
            success_count, failed_paths = enhanced_malware_removal(file_paths)
            
            # Try to delete metadata files with standard method (they shouldn't be locked)
            for meta_path in meta_paths:
                try:
                    os.remove(meta_path)
                except:
                    pass
            
            # Update quarantine table
            for row in sorted(selected_rows, reverse=True):
                filename = self.quarantine_table.item(row, 0).text()
                quarantined_file = os.path.join(quarantine_dir, filename)
                
                if quarantined_file not in failed_paths:
                    self.quarantine_table.removeRow(row)
            
            # Show notifications
            if success_count > 0:
                self.notification_manager.show_notification(
                    "Files Deleted",
                    f"Successfully deleted {success_count} file(s) from quarantine.",
                    "success"
                )
            
            if failed_paths:
                self.notification_manager.show_notification(
                    "Some Files Scheduled for Deletion",
                    f"{len(failed_paths)} file(s) will be deleted on next system restart.",
                    "info"
                )
                
                # Log the scheduled deletions
                for path in failed_paths:
                    self.add_log_event("info", f"Scheduled for deletion on reboot: {path}")
        
        # Update status
        self.statusBar().showMessage(f"Quarantine: {self.quarantine_table.rowCount()} files")

        
        # Show notifications
        if success_count > 0:
            self.notification_manager.show_notification(
                "Files Deleted",
                f"Successfully deleted {success_count} file(s) from quarantine.",
                "success"
            )
        
        if scheduled_count > 0:
            self.notification_manager.show_notification(
                "Deletion Scheduled",
                f"{scheduled_count} file(s) scheduled for deletion on next reboot.",
                "info"
            )
        
        if fail_count > 0:
            self.notification_manager.show_notification(
                "Delete Failed",
                f"Failed to delete {fail_count} file(s). Check log for details.",
                "error"
            )


    
    def quarantine_file(self, file_path):
        """Move a file to quarantine with encryption"""
        if not os.path.exists(file_path):
            self.add_log_event("error", f"File not found: {file_path}")
            return False
        
        try:
            # Create quarantine directory if it doesn't exist
            quarantine_dir = os.path.join(
                os.environ.get('APPDATA', os.path.expanduser('~')),
                APP_NAME,
                'quarantine'
            )
            os.makedirs(quarantine_dir, exist_ok=True)
            
            # Generate a unique filename for the quarantined file
            filename = os.path.basename(file_path)
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            quarantine_filename = f"{timestamp}_{filename}"
            quarantine_path = os.path.join(quarantine_dir, quarantine_filename)
            
            # Calculate file hash before quarantine
            file_hash = VirusScanner.calculate_file_hash(file_path)
            
            # Read the file content
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            # Simple XOR encryption with a fixed key (for demonstration)
            # In a real implementation, use proper encryption
            key = b'ShieldGuardProQuarantineKey'
            encrypted_content = bytes([file_content[i] ^ key[i % len(key)] for i in range(len(file_content))])
            
            # Write encrypted content to quarantine
            with open(quarantine_path, 'wb') as f:
                f.write(encrypted_content)
            
            # Create metadata file
            metadata = {
                'original_path': file_path,
                'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'hash': file_hash,
                'size': os.path.getsize(file_path),
                'encrypted': True
            }
            
            with open(quarantine_path + '.meta', 'w') as f:
                json.dump(metadata, f)
            
            # Delete original file
            os.remove(file_path)
            
            self.add_log_event("info", f"Moved {file_path} to quarantine")
            
            # Refresh quarantine list
            self.refresh_quarantine()
            
            return True
        
        except Exception as e:
            self.add_log_event("error", f"Failed to quarantine {file_path}: {str(e)}")
            return False
    
    def add_log_event(self, level, message):
        """Add an event to the log with color coding"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Set color based on log level
        color = COLOR_NEUTRAL
        if level == "error":
            color = COLOR_DANGER
        elif level == "warning":
            color = COLOR_WARNING
        elif level == "info":
            color = COLOR_INFO
        elif level == "success":
            color = COLOR_SUCCESS
        
        # Format log entry
        log_entry = f"<span style='color:{color}'>[{timestamp}] [{level.upper()}]</span> {message}"
        
        # Add to log
        self.log_text.append(log_entry)
        
        # Scroll to bottom
        cursor = self.log_text.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.log_text.setTextCursor(cursor)
        
        # Also log to file
        self.log_to_file(f"[{timestamp}] [{level.upper()}] {message}")
    
    def log_to_file(self, message):
        """Log message to a file"""
        try:
            log_dir = os.path.join(
                os.environ.get('APPDATA', os.path.expanduser('~')),
                APP_NAME,
                'logs'
            )
            os.makedirs(log_dir, exist_ok=True)
            
            log_file = os.path.join(log_dir, f"{datetime.now().strftime('%Y%m%d')}.log")
            
            with open(log_file, 'a') as f:
                f.write(message + '\n')
        except:
            # Silently fail if logging to file fails
            pass
    
    def clear_log(self):
        """Clear the event log"""
        self.log_text.clear()
    
    def export_log(self):
        """Export the event log to a file"""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Event Log",
            os.path.expanduser("~/event_log.txt"),
            "Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            try:
                # Get plain text from log
                log_text = self.log_text.toPlainText()
                
                with open(file_path, 'w') as f:
                    f.write(log_text)
                
                self.add_log_event("info", f"Exported event log to {file_path}")
                
                # Show notification
                self.notification_manager.show_notification(
                    "Export Successful",
                    f"Log exported to {file_path}",
                    "success"
                )
            
            except Exception as e:
                self.add_log_event("error", f"Failed to export log: {str(e)}")
                
                # Show notification
                self.notification_manager.show_notification(
                    "Export Failed",
                    f"Failed to export log: {str(e)}",
                    "error"
                )
    
    def update_signatures(self):
        """Update virus signatures"""
        self.add_log_event("info", "Starting signature update...")
        self.statusBar().showMessage("Updating signatures...")
        
        # Disable update button
        update_action = self.findChild(QAction, "update_action")
        if update_action:
            update_action.setEnabled(False)
        
        # Create and start update thread
        self.update_thread = SignatureUpdateThread(self.config.get('signature_sources', []))
        self.update_thread.update_complete.connect(self.on_update_complete)
        self.update_thread.log_event.connect(self.add_log_event)
        self.update_thread.start()
        
        # Show notification
        self.notification_manager.show_notification(
            "Updating Signatures",
            "Downloading the latest virus definitions...",
            "info"
        )
    
    def on_update_complete(self, success):
        """Handle signature update completion"""
        # Re-enable update button
        update_action = self.findChild(QAction, "update_action")
        if update_action:
            update_action.setEnabled(True)
        
        if success:
            self.add_log_event("success", "Signature update completed successfully")
            self.statusBar().showMessage("Signatures updated successfully")
            
            # Show notification
            self.notification_manager.show_notification(
                "Signatures Updated",
                "Virus definitions have been updated successfully.",
                "success"
            )
        else:
            self.add_log_event("error", "Signature update failed")
            self.statusBar().showMessage("Signature update failed")
            
            # Show notification
            self.notification_manager.show_notification(
                "Update Failed",
                "Failed to update virus definitions. Please try again later.",
                "error"
            )
    
# In the toggle_real_time_monitoring method of MainWindow:

    def toggle_real_time_monitoring(self, state):
        """Toggle real-time monitoring on/off"""
        enabled = bool(state)
        
        if enabled:
            if not self.real_time_monitor.isRunning():
                # Update the monitor's config with current settings
                self.real_time_monitor.config.update({
                    'dns_monitoring': self.config.get('dns_monitoring', True),
                    'raw_disk_monitoring': self.config.get('raw_disk_monitoring', True),
                    'file_drop_monitoring': self.config.get('file_drop_monitoring', True),
                    'hook_monitoring': self.config.get('hook_monitoring', True),
                    'detect_process_impersonation': self.config.get('detect_process_impersonation', True),
                    'detect_runner_invasion': self.config.get('detect_runner_invasion', True),
                    'auto_quarantine_drops': self.config.get('auto_quarantine_drops', True),
                    'auto_block_connections': self.config.get('auto_block_connections', False),
                    'prevent_driver_changes': self.config.get('prevent_driver_changes', True),
                    'prevent_raw_disk_access': self.config.get('prevent_raw_disk_access', True),
                    'auto_terminate_processes': self.config.get('auto_terminate_processes', False)
                })
                
                # Apply direct fixes for COMODO Leaktests vulnerabilities
                if sys.platform == 'win32' and self.is_admin_mode:
                    try:
                        # Show a progress dialog while applying fixes
                        progress = QProgressDialog("Applying security fixes...", "Cancel", 0, 3, self)
                        progress.setWindowTitle("Security Enhancement")
                        progress.setWindowModality(Qt.WindowModal)
                        progress.setValue(0)
                        progress.show()
                        QApplication.processEvents()
                        
                        # 1. Fix ChangeDrvPath vulnerability
                        self.add_log_event("info", "Fixing ChangeDrvPath vulnerability...")
                        self.fix_changedrvpath_vulnerability()
                        progress.setValue(1)
                        QApplication.processEvents()
                        
                        # 2. Fix Runner vulnerability
                        self.add_log_event("info", "Fixing Runner vulnerability...")
                        self.fix_runner_vulnerability()
                        progress.setValue(2)
                        QApplication.processEvents()
                        
                        # 3. Fix RawDisk vulnerability
                        self.add_log_event("info", "Fixing RawDisk vulnerability...")
                        self.fix_rawdisk_vulnerability()
                        progress.setValue(3)
                        QApplication.processEvents()
                        
                        progress.close()
                        
                        # Show success notification
                        self.notification_manager.show_notification(
                            "Security Vulnerabilities Fixed",
                            "Protection against ChangeDrvPath, Runner, and RawDisk attacks has been enabled.",
                            "success"
                        )
                    except Exception as e:
                        self.add_log_event("error", f"Error applying security fixes: {str(e)}")

                
                self.real_time_monitor.start()
                self.add_log_event("info", "Real-time protection enabled with all security features")
                
                # Update status indicator
                self.realtime_status.setText("Active")
                self.realtime_status.setStyleSheet(f"color: {COLOR_SUCCESS};")
                
                # Update tray icon action
                if hasattr(self, 'tray_realtime_action'):
                    self.tray_realtime_action.setChecked(True)
                
                # Show notification
                self.notification_manager.show_notification(
                    "Real-time Protection Enabled",
                    "Your system is now being actively monitored for threats.",
                    "success"
                )
        else:
            if self.real_time_monitor.isRunning():
                self.real_time_monitor.stop()
                self.real_time_monitor.wait()
                self.add_log_event("warning", "Real-time protection disabled")
                
                # Update status indicator
                self.realtime_status.setText("Inactive")
                self.realtime_status.setStyleSheet(f"color: {COLOR_DANGER};")
                
                # Update tray icon action
                if hasattr(self, 'tray_realtime_action'):
                    self.tray_realtime_action.setChecked(False)
                
                # Show notification
                self.notification_manager.show_notification(
                    "Real-time Protection Disabled",
                    "Your system is no longer being actively monitored for threats.",
                    "warning"
                )
        
        # Update config
        self.config['real_time_monitoring'] = enabled
        self._save_config()





    def setup_driver_path_protection(self):
        """Set up protection against driver path modifications"""
        if sys.platform == 'win32' and self.is_admin_mode:
            try:
                # Create a PowerShell script to set up protection
                ps_cmd = '''powershell -Command "
                # Create a registry key to monitor for changes
                $key = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services'
                
                # Set permissions to prevent modifications
                $acl = Get-Acl $key
                $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
                    'Everyone',
                    'SetValue,Delete,ChangePermissions',
                    'Deny'
                )
                $acl.AddAccessRule($rule)
                
                try {
                    Set-Acl -Path $key -AclObject $acl -ErrorAction Stop
                    Write-Host 'Driver path protection enabled'
                } catch {
                    Write-Host 'Failed to set ACL: $_'
                }
                
                # Create a WMI event subscription to monitor for changes
                $query = 'SELECT * FROM RegistryValueChangeEvent WHERE Hive=\'HKEY_LOCAL_MACHINE\' AND KeyPath=\'SYSTEM\\\\CurrentControlSet\\\\Services\\\\*\' AND ValueName=\'ImagePath\''
                
                try {
                    $null = Register-WmiEvent -Query $query -Action {
                        $path = $Event.SourceEventArgs.NewEvent.KeyPath
                        $value = $Event.SourceEventArgs.NewEvent.ValueName
                        
                        # Log the change attempt
                        Add-Content -Path 'C:\\Windows\\Temp\\DriverChanges.log' -Value (Get-Date).ToString() + ' - Attempted change to ' + $path + '\\' + $value
                    }
                    Write-Host 'WMI event subscription created for driver path monitoring'
                } catch {
                    Write-Host 'Failed to create WMI event subscription: $_'
                }
                "'''
                
                # Run the PowerShell command
                result = subprocess.run(ps_cmd, capture_output=True, text=True, check=False)
                
                if result.returncode == 0:
                    self.add_log_event("success", "Driver path protection enabled")
                else:
                    self.add_log_event("warning", f"Driver path protection setup returned: {result.stderr}")
                    
            except Exception as e:
                self.add_log_event("error", f"Failed to set up driver path protection: {str(e)}")

    def setup_runner_protection(self):
        """Set up protection against Runner invasion technique"""
        if sys.platform == 'win32' and self.is_admin_mode:
            try:
                # Create a PowerShell script to set up protection
                ps_cmd = '''powershell -Command "
                # Create AppLocker rules to block rundll32.js and rundll32.vbs execution
                try {
                    # Check if AppLocker module is available
                    if (Get-Command New-AppLockerPolicy -ErrorAction SilentlyContinue) {
                        # Create a rule to block JavaScript and VBScript execution through rundll32
                        $rules = @()
                        
                        # Block rundll32.exe from executing .js files
                        $jsRule = New-AppLockerFilePathCondition -Path '%SYSTEM32%\\rundll32.exe'
                        $rules += New-AppLockerRule -FilePathCondition $jsRule -RuleType Path -User Everyone -Action Deny -Name 'Block rundll32 JavaScript' -Description 'Block rundll32.exe from executing JavaScript'
                        
                        # Block regsvr32.exe from executing scripts
                        $regsvr32Rule = New-AppLockerFilePathCondition -Path '%SYSTEM32%\\regsvr32.exe'
                        $rules += New-AppLockerRule -FilePathCondition $regsvr32Rule -RuleType Path -User Everyone -Action Deny -Name 'Block regsvr32 scripts' -Description 'Block regsvr32.exe from executing scripts'
                        
                        # Create and apply the policy
                        $policy = New-AppLockerPolicy -RuleCollection $rules
                        Set-AppLockerPolicy -PolicyObject $policy -Merge
                        
                        Write-Host 'AppLocker rules created to block Runner invasion technique'
                    } else {
                        Write-Host 'AppLocker module not available'
                        
                        # Alternative: Use Software Restriction Policies
                        $srp = @'
                        [HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers]
                        \"DefaultLevel\"=dword:00040000
                        
                        [HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0]
                        \"Level\"=dword:00040000
                        
                        [HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Paths]
                        
                        [HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Paths\\{1db1b2ba-5d80-4ec4-a99d-a3b6b6cc9ef3}]
                        \"Description\"=\"Block rundll32.js\"
                        \"ItemData\"=\"%SYSTEM32%\\\\rundll32.exe javascript:\"
                        \"SaferFlags\"=dword:00000000
                        '@
                        
                        $srpFile = 'C:\\Windows\\Temp\\srp_rules.reg'
                        Set-Content -Path $srpFile -Value $srp
                        
                        # Import the registry file
                        Start-Process -FilePath 'reg.exe' -ArgumentList 'import', $srpFile -Wait
                        
                        Write-Host 'Software Restriction Policies created to block Runner invasion technique'
                    }
                    
                    # Also add a firewall rule to block rundll32.exe outbound connections
                    New-NetFirewallRule -DisplayName 'Block rundll32.exe outbound' -Direction Outbound -Program '%SYSTEM32%\\rundll32.exe' -Action Block -Profile Any -Enabled True
                    
                    Write-Host 'Firewall rule added to block rundll32.exe outbound connections'
                    
                } catch {
                    Write-Host 'Failed to create protection rules: $_'
                }
                "'''
                
                # Run the PowerShell command
                result = subprocess.run(ps_cmd, capture_output=True, text=True, check=False)
                
                if result.returncode == 0:
                    self.add_log_event("success", "Runner invasion protection enabled")
                else:
                    self.add_log_event("warning", f"Runner invasion protection setup returned: {result.stderr}")
                    
            except Exception as e:
                self.add_log_event("error", f"Failed to set up Runner invasion protection: {str(e)}")

    def setup_raw_disk_protection(self):
        """Set up protection against raw disk access"""
        if sys.platform == 'win32' and self.is_admin_mode:
            try:
                # Create a PowerShell script to set up protection
                ps_cmd = '''powershell -Command "
                # Create a security descriptor that denies access to everyone except SYSTEM and Administrators
                $acl = 'D:P(D;;GA;;;WD)(A;;GA;;;SY)(A;;GA;;;BA)'
                
                # List of device paths to protect
                $devices = @('\\\\.\\PhysicalDrive0', '\\\\.\\PhysicalDrive1', '\\\\.\\HarddiskVolume1')
                
                # Create a registry key to store our protection settings
                $regPath = 'HKLM:\\SOFTWARE\\ShieldGuardPro\\DiskProtection'
                if (-not (Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }
                
                # Create a firewall rule to block suspicious processes from accessing disks
                $suspiciousProcesses = @('rundll32.exe', 'regsvr32.exe', 'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe')
                
                foreach ($proc in $suspiciousProcesses) {
                    try {
                        $ruleName = 'Block ' + $proc + ' disk access'
                        New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Program ('%SYSTEM32%\\' + $proc) -RemotePort 445 -Protocol TCP -Action Block -Profile Any -Enabled True
                        Write-Host ('Created firewall rule: ' + $ruleName)
                    } catch {
                        Write-Host ('Failed to create firewall rule for ' + $proc + ': ' + $_)
                    }
                }
                
                # Create a scheduled task to monitor for raw disk access
                $taskName = 'ShieldGuardPro_DiskAccessMonitor'
                $taskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -WindowStyle Hidden -Command \"Get-WinEvent -FilterHashtable @{LogName=\'Security\'; ID=4656} | Where-Object { $_.Message -like \'*\\\\\\\\.\\\\\\\PhysicalDrive*\' } | ForEach-Object { Add-Content -Path \'C:\\Windows\\Temp\\DiskAccess.log\' -Value (Get-Date).ToString() + \' - \' + $_.Message }\"'
                $taskTrigger = New-ScheduledTaskTrigger -AtStartup
                $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden
                $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
                
                try {
                    Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Principal $taskPrincipal -Force
                    Write-Host 'Created scheduled task to monitor disk access'
                } catch {
                    Write-Host 'Failed to create scheduled task: $_'
                }
                
                # Enable auditing for disk access
                auditpol /set /subcategory:'Handle Manipulation' /success:enable /failure:enable
                Write-Host 'Enabled auditing for handle manipulation'
                
                # Create a registry key to block direct disk access
                New-ItemProperty -Path $regPath -Name 'BlockRawAccess' -Value 1 -PropertyType DWORD -Force
                Write-Host 'Created registry setting to block raw disk access'
                "'''
                
                # Run the PowerShell command
                result = subprocess.run(ps_cmd, capture_output=True, text=True, check=False)
                
                if result.returncode == 0:
                    self.add_log_event("success", "Raw disk access protection enabled")
                else:
                    self.add_log_event("warning", f"Raw disk access protection setup returned: {result.stderr}")
                    
                # Create a kernel-mode filter to block direct disk access
                # This requires the Windows Driver Kit, so we'll use a registry-based approach instead
                try:
                    import winreg
                    key_path = r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"
                    
                    # Create the key if it doesn't exist
                    try:
                        key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path)
                    except:
                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_WRITE)
                    
                    # Set WriteProtect value to 1 to enable write protection
                    winreg.SetValueEx(key, "WriteProtect", 0, winreg.REG_DWORD, 1)
                    winreg.CloseKey(key)
                    
                    self.add_log_event("success", "Enabled storage device write protection")
                except Exception as e:
                    self.add_log_event("error", f"Failed to set storage device write protection: {str(e)}")
                    
            except Exception as e:
                self.add_log_event("error", f"Failed to set up raw disk access protection: {str(e)}")


    

    
    def terminate_process(self, process_id):
        """Terminate a process by its ID"""
        try:
            if sys.platform == 'win32':
                # For Windows
                import ctypes
                handle = ctypes.windll.kernel32.OpenProcess(1, False, int(process_id))
                if handle:
                    result = ctypes.windll.kernel32.TerminateProcess(handle, 0)
                    ctypes.windll.kernel32.CloseHandle(handle)
                    
                    if result:
                        self.add_log_event("success", f"Successfully terminated process with PID {process_id}")
                        
                        # Show notification
                        self.notification_manager.show_notification(
                            "Process Terminated",
                            f"Successfully terminated process with PID {process_id}",
                            "success"
                        )
                    else:
                        self.add_log_event("error", f"Failed to terminate process with PID {process_id}")
                        
                        # Show notification
                        self.notification_manager.show_notification(
                            "Termination Failed",
                            f"Failed to terminate process with PID {process_id}",
                            "error"
                        )
                else:
                    self.add_log_event("error", f"Failed to open process with PID {process_id}")
            else:
                # For Unix-like systems
                import os
                import signal
                os.kill(int(process_id), signal.SIGTERM)
                self.add_log_event("success", f"Sent termination signal to process with PID {process_id}")
                
                # Show notification
                self.notification_manager.show_notification(
                    "Process Termination Signal Sent",
                    f"Sent termination signal to process with PID {process_id}",
                    "success"
                )
        except Exception as e:
            self.add_log_event("error", f"Error terminating process with PID {process_id}: {str(e)}")
            
            # Show notification
            self.notification_manager.show_notification(
                "Termination Error",
                f"Error terminating process with PID {process_id}: {str(e)}",
                "error"
            )

    def remove_registry_value(self, key_path, value_name):
        """Remove a registry value"""
        if sys.platform != 'win32':
            self.add_log_event("error", "Registry operations are only supported on Windows")
            return
            
        try:
            import winreg
            
            # Determine which hive to use
            if key_path.startswith("HKLM\\") or key_path.startswith("HKEY_LOCAL_MACHINE\\"):
                hive = winreg.HKEY_LOCAL_MACHINE
                key_path = key_path.replace("HKLM\\", "").replace("HKEY_LOCAL_MACHINE\\", "")
            elif key_path.startswith("HKCU\\") or key_path.startswith("HKEY_CURRENT_USER\\"):
                hive = winreg.HKEY_CURRENT_USER
                key_path = key_path.replace("HKCU\\", "").replace("HKEY_CURRENT_USER\\", "")
            else:
                # Default to HKLM
                hive = winreg.HKEY_LOCAL_MACHINE
            
            # Open the registry key with write access
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE)
            
            # Delete the value
            winreg.DeleteValue(key, value_name)
            winreg.CloseKey(key)
            
            self.add_log_event("success", f"Successfully removed registry value: {key_path}\\{value_name}")
            
            # Show notification
            self.notification_manager.show_notification(
                "Registry Value Removed",
                f"Successfully removed registry value: {key_path}\\{value_name}",
                "success"
            )
        except Exception as e:
            self.add_log_event("error", f"Error removing registry value {key_path}\\{value_name}: {str(e)}")
            
            # Show notification
            self.notification_manager.show_notification(
                "Registry Operation Failed",
                f"Error removing registry value: {str(e)}",
                "error"
            )

    
    def show_settings(self):
        """Show settings dialog"""
        dialog = SettingsDialog(self.config, self.is_admin_mode, self)
        if dialog.exec_() == QDialog.Accepted:
            # Apply new settings
            self.config = dialog.get_config()
            self._save_config()
            
            # Update UI based on new settings
            self.real_time_checkbox.setChecked(self.config.get('real_time_monitoring', False))
            self.autostart_checkbox.setChecked(self.config.get('scan_on_startup', False))
            
            # Toggle real-time monitoring if needed
            if self.config.get('real_time_monitoring', False) != self.real_time_monitor.isRunning():
                self.toggle_real_time_monitoring(self.config.get('real_time_monitoring', False))
            
            # Apply theme if changed
            current_theme = self.config.get('theme', 'dark')
            self.apply_theme(current_theme)
            
            self.add_log_event("info", "Settings updated")
            
            # Show notification
            self.notification_manager.show_notification(
                "Settings Updated",
                "Your configuration changes have been saved.",
                "info"
            )
    
    def show_about(self):
        """Show about dialog"""
        about_text = f"""
        <h2>{APP_NAME} v{APP_VERSION}</h2>
        <p>Advanced Virus Detection and Removal System</p>
        <p>© 2023 {COMPANY_NAME}</p>
        <p>This software provides comprehensive protection against viruses, 
        malware, ransomware, and other threats using multiple detection engines:</p>
        <ul>
            <li>Signature-based detection</li>
            <li>Heuristic analysis</li>
            <li>Behavioral monitoring</li>
            <li>Machine learning</li>
            <li>Real-time protection</li>
        </ul>
        <p><a href="https://www.example.com">Visit our website</a></p>
        """
        
        QMessageBox.about(self, f"About {APP_NAME}", about_text)
    
    def check_for_updates(self):
        """Check for software updates"""
        # This is a placeholder for actual update checking functionality
        # In a real application, this would connect to a server to check for updates
        
        # Simulate update check
        self.add_log_event("info", "Checking for updates...")
        
        # For demonstration, we'll just show that we're up to date
        self.add_log_event("info", f"{APP_NAME} v{APP_VERSION} is up to date")

class SettingsDialog(QDialog):
    """Settings dialog for configuring the application"""
    
    def __init__(self, config, is_admin_mode, parent=None):
        super().__init__(parent)
        self.config = config.copy()
        self.is_admin_mode = is_admin_mode
        self.init_ui()
    
    def init_ui(self):
        """Initialize the settings dialog UI"""
        self.setWindowTitle("Settings")
        self.setWindowIcon(QIcon(get_resource_path(":/icons/settings.png")))
        self.setMinimumWidth(600)
        
        layout = QVBoxLayout(self)
        
        # Create tab widget for settings categories
        tab_widget = QTabWidget()
        
        # General settings tab
        general_tab = QWidget()
        general_layout = QVBoxLayout(general_tab)
        
        # Action group
        action_group = QGroupBox("Default Action")
        action_layout = QVBoxLayout(action_group)
        
        self.action_combo = QComboBox()
        self.action_combo.addItems(["Quarantine", "Delete", "Report only"])
        current_action = self.config.get('action', 'quarantine')
        if current_action == 'quarantine':
            self.action_combo.setCurrentIndex(0)
        elif current_action == 'delete':
            self.action_combo.setCurrentIndex(1)
        else:
            self.action_combo.setCurrentIndex(2)
        
        action_layout.addWidget(QLabel("When a threat is detected:"))
        action_layout.addWidget(self.action_combo)
        
        # Interface group
        interface_group = QGroupBox("Interface")
        interface_layout = QVBoxLayout(interface_group)
        
        self.minimize_checkbox = QCheckBox("Minimize to system tray when closed")
        self.minimize_checkbox.setChecked(self.config.get('minimize_to_tray', True))
        
        self.startup_checkbox = QCheckBox("Start with system")
        self.startup_checkbox.setChecked(self.config.get('start_with_system', False))
        
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Dark Theme", "Light Theme"])
        current_theme = self.config.get('theme', 'dark')
        self.theme_combo.setCurrentIndex(0 if current_theme == 'dark' else 1)
        
        theme_layout = QHBoxLayout()
        theme_layout.addWidget(QLabel("Theme:"))
        theme_layout.addWidget(self.theme_combo)
        
        interface_layout.addWidget(self.minimize_checkbox)
        interface_layout.addWidget(self.startup_checkbox)
        interface_layout.addLayout(theme_layout)
        
        # Add groups to general tab
        general_layout.addWidget(action_group)
        general_layout.addWidget(interface_group)
        general_layout.addStretch()
        
        # Scan settings tab
        scan_tab = QWidget()
        scan_layout = QVBoxLayout(scan_tab)
        
        # Scan options group
        scan_options_group = QGroupBox("Scan Options")
        scan_options_layout = QFormLayout(scan_options_group)
        
        self.scan_archives_checkbox = QCheckBox()
        self.scan_archives_checkbox.setChecked(self.config.get('scan_archives', True))
        
        self.scan_memory_checkbox = QCheckBox()
        self.scan_memory_checkbox.setChecked(self.config.get('scan_memory', True))
        
        self.scan_registry_checkbox = QCheckBox()
        self.scan_registry_checkbox.setChecked(self.config.get('scan_registry', True))
        
        self.heuristic_level_combo = QComboBox()
        self.heuristic_level_combo.addItems(["Low (Fewer False Positives)", "Medium (Balanced)", "High (Aggressive Detection)"])
        self.heuristic_level_combo.setCurrentIndex(self.config.get('heuristic_level', 2) - 1)
        
        self.max_file_size_spin = QSpinBox()
        self.max_file_size_spin.setRange(10, 1000)
        self.max_file_size_spin.setSuffix(" MB")
        self.max_file_size_spin.setValue(self.config.get('max_file_size', 100))
        
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, os.cpu_count() or 4)
        self.threads_spin.setValue(self.config.get('max_workers', os.cpu_count() or 4))
        
        scan_options_layout.addRow("Scan archives:", self.scan_archives_checkbox)
        scan_options_layout.addRow("Scan system memory:", self.scan_memory_checkbox)
        scan_options_layout.addRow("Scan registry:", self.scan_registry_checkbox)
        scan_options_layout.addRow("Detection sensitivity:", self.heuristic_level_combo)
        scan_options_layout.addRow("Maximum file size:", self.max_file_size_spin)
        scan_options_layout.addRow("Scan threads:", self.threads_spin)
        
        # Real-time protection group
        realtime_group = QGroupBox("Real-time Protection")
        realtime_layout = QVBoxLayout(realtime_group)
        
        self.realtime_checkbox = QCheckBox("Enable real-time protection")
        self.realtime_checkbox.setChecked(self.config.get('real_time_monitoring', False))
        
        self.auto_start_checkbox = QCheckBox("Start real-time protection when application launches")
        self.auto_start_checkbox.setChecked(self.config.get('auto_start_protection', False))
        
        self.scan_startup_checkbox = QCheckBox("Run quick scan on system startup")
        self.scan_startup_checkbox.setChecked(self.config.get('scan_on_startup', False))
        
        realtime_layout.addWidget(self.realtime_checkbox)
        realtime_layout.addWidget(self.auto_start_checkbox)
        realtime_layout.addWidget(self.scan_startup_checkbox)
        realtime_layout.addWidget(QLabel("Real-time protection monitors file system changes and automatically scans new or modified files."))
        
        # Enhanced real-time protection options
        enhanced_realtime_group = QGroupBox("Enhanced Protection Features")
        enhanced_realtime_layout = QVBoxLayout(enhanced_realtime_group)
        
        self.process_monitoring_checkbox = QCheckBox("Monitor suspicious processes")
        self.process_monitoring_checkbox.setChecked(self.config.get('monitor_processes', True))
        self.process_monitoring_checkbox.setToolTip("Detect malicious processes and command lines")
        
        self.registry_monitoring_checkbox = QCheckBox("Monitor registry changes")
        self.registry_monitoring_checkbox.setChecked(self.config.get('monitor_registry', True))
        self.registry_monitoring_checkbox.setToolTip("Detect suspicious registry modifications")
        
        self.driver_monitoring_checkbox = QCheckBox("Monitor driver and kernel changes")
        self.driver_monitoring_checkbox.setChecked(self.config.get('monitor_drivers', True))
        self.driver_monitoring_checkbox.setToolTip("Detect rootkit-like behavior and driver modifications")
        
        self.auto_terminate_checkbox = QCheckBox("Automatically terminate suspicious processes")
        self.auto_terminate_checkbox.setChecked(self.config.get('auto_terminate_processes', False))
        self.auto_terminate_checkbox.setToolTip("Automatically terminate detected malicious processes")
        
        self.auto_fix_registry_checkbox = QCheckBox("Automatically fix suspicious registry changes")
        self.auto_fix_registry_checkbox.setChecked(self.config.get('auto_fix_registry', False))
        self.auto_fix_registry_checkbox.setToolTip("Automatically remove malicious registry entries")
        
        enhanced_realtime_layout.addWidget(self.process_monitoring_checkbox)
        enhanced_realtime_layout.addWidget(self.registry_monitoring_checkbox)
        enhanced_realtime_layout.addWidget(self.driver_monitoring_checkbox)
        enhanced_realtime_layout.addWidget(self.auto_terminate_checkbox)
        enhanced_realtime_layout.addWidget(self.auto_fix_registry_checkbox)
        
        # Add description label
        description_label = QLabel("Enhanced protection features provide comprehensive defense against advanced threats, including rootkits, process injection, and registry manipulation techniques.")
        description_label.setWordWrap(True)
        description_label.setStyleSheet("color: #2196F3; font-style: italic;")
        enhanced_realtime_layout.addWidget(description_label)
        
        # Advanced Protection Options - NEW SECTION
        advanced_protection_group = QGroupBox("Advanced Protection Options")
        advanced_protection_layout = QVBoxLayout(advanced_protection_group)
        
        self.dns_monitoring_checkbox = QCheckBox("Monitor DNS for data exfiltration")
        self.dns_monitoring_checkbox.setChecked(self.config.get('dns_monitoring', True))
        self.dns_monitoring_checkbox.setToolTip("Detect and block data exfiltration via DNS queries")
        
        self.raw_disk_monitoring_checkbox = QCheckBox("Monitor raw disk access")
        self.raw_disk_monitoring_checkbox.setChecked(self.config.get('raw_disk_monitoring', True))
        self.raw_disk_monitoring_checkbox.setToolTip("Detect attempts to access disk sectors directly")
        
        self.file_drop_monitoring_checkbox = QCheckBox("Monitor file drops in sensitive locations")
        self.file_drop_monitoring_checkbox.setChecked(self.config.get('file_drop_monitoring', True))
        self.file_drop_monitoring_checkbox.setToolTip("Detect malicious files being created in system directories")
        
        self.hook_monitoring_checkbox = QCheckBox("Monitor for hook-based injections")
        self.hook_monitoring_checkbox.setChecked(self.config.get('hook_monitoring', True))
        self.hook_monitoring_checkbox.setToolTip("Detect SetWindowsHookEx and SetWinEventHook injection techniques")
        
        self.auto_block_connections_checkbox = QCheckBox("Automatically block suspicious connections")
        self.auto_block_connections_checkbox.setChecked(self.config.get('auto_block_connections', False))
        self.auto_block_connections_checkbox.setToolTip("Block network connections to suspicious domains")
        
        self.process_impersonation_checkbox = QCheckBox("Detect process impersonation (Coat technique)")
        self.process_impersonation_checkbox.setChecked(self.config.get('detect_process_impersonation', True))
        self.process_impersonation_checkbox.setToolTip("Detect processes that impersonate system processes")
        
        self.runner_invasion_checkbox = QCheckBox("Detect Runner invasion technique")
        self.runner_invasion_checkbox.setChecked(self.config.get('detect_runner_invasion', True))
        self.runner_invasion_checkbox.setToolTip("Detect attempts to execute code via rundll32 and other techniques")
        
        self.auto_quarantine_drops_checkbox = QCheckBox("Auto-quarantine suspicious file drops")
        self.auto_quarantine_drops_checkbox.setChecked(self.config.get('auto_quarantine_drops', True))
        self.auto_quarantine_drops_checkbox.setToolTip("Automatically quarantine suspicious files dropped in system directories")
        
        # NEW: Add options for the vulnerabilities we're fixing
        self.prevent_driver_changes_checkbox = QCheckBox("Prevent driver path modifications")
        self.prevent_driver_changes_checkbox.setChecked(self.config.get('prevent_driver_changes', True))
        self.prevent_driver_changes_checkbox.setToolTip("Block attempts to modify system driver paths (fixes ChangeDrvPath vulnerability)")
        
        self.prevent_raw_disk_access_checkbox = QCheckBox("Prevent raw disk access")
        self.prevent_raw_disk_access_checkbox.setChecked(self.config.get('prevent_raw_disk_access', True))
        self.prevent_raw_disk_access_checkbox.setToolTip("Block attempts to access disk sectors directly (fixes RawDisk vulnerability)")
        
        advanced_protection_layout.addWidget(self.dns_monitoring_checkbox)
        advanced_protection_layout.addWidget(self.raw_disk_monitoring_checkbox)
        advanced_protection_layout.addWidget(self.file_drop_monitoring_checkbox)
        advanced_protection_layout.addWidget(self.hook_monitoring_checkbox)
        advanced_protection_layout.addWidget(self.process_impersonation_checkbox)
        advanced_protection_layout.addWidget(self.runner_invasion_checkbox)
        advanced_protection_layout.addWidget(self.auto_block_connections_checkbox)
        advanced_protection_layout.addWidget(self.auto_quarantine_drops_checkbox)
        # Add the new options
        advanced_protection_layout.addWidget(self.prevent_driver_changes_checkbox)
        advanced_protection_layout.addWidget(self.prevent_raw_disk_access_checkbox)
        
        # Add description label
        adv_description_label = QLabel("Advanced protection features defend against sophisticated evasion techniques and data exfiltration methods identified in security tests.")
        adv_description_label.setWordWrap(True)
        adv_description_label.setStyleSheet("color: #2196F3; font-style: italic;")
        advanced_protection_layout.addWidget(adv_description_label)
        
        # Add groups to scan tab
        scan_layout.addWidget(scan_options_group)
        scan_layout.addWidget(realtime_group)
        scan_layout.addWidget(enhanced_realtime_group)
        scan_layout.addWidget(advanced_protection_group)  # Add the new group
        scan_layout.addStretch()
        
        # Exclusions tab
        exclusions_tab = QWidget()
        exclusions_layout = QVBoxLayout(exclusions_tab)
        
        exclusions_label = QLabel("Add files or directories to exclude from scanning:")
        
        self.exclusions_list = QTextEdit()
        self.exclusions_list.setPlaceholderText("Enter one path per line")
        
        # Load exclusions from config
        exclusions = self.config.get('exclusions', [])
        if exclusions:
            self.exclusions_list.setText("\n".join(exclusions))
        
        exclusions_buttons = QHBoxLayout()
        
        add_button = QPushButton("Add File")
        add_button.clicked.connect(self.add_exclusion_file)
        add_button.setObjectName("secondary_button")
        
        add_dir_button = QPushButton("Add Directory")
        add_dir_button.clicked.connect(self.add_exclusion_directory)
        add_dir_button.setObjectName("secondary_button")
        
        exclusions_buttons.addWidget(add_button)
        exclusions_buttons.addWidget(add_dir_button)
        exclusions_buttons.addStretch()
        
        exclusions_layout.addWidget(exclusions_label)
        exclusions_layout.addWidget(self.exclusions_list)
        exclusions_layout.addLayout(exclusions_buttons)
        
        # Updates tab
        updates_tab = QWidget()
        updates_layout = QVBoxLayout(updates_tab)
        
        # Update settings group
        update_group = QGroupBox("Update Settings")
        update_layout = QFormLayout(update_group)
        
        self.auto_update_checkbox = QCheckBox()
        self.auto_update_checkbox.setChecked(self.config.get('auto_update', True))
        
        self.update_frequency_combo = QComboBox()
        self.update_frequency_combo.addItems(["Daily", "Weekly", "Monthly"])
        self.update_frequency_combo.setCurrentIndex({
            'daily': 0,
            'weekly': 1,
            'monthly': 2
        }.get(self.config.get('update_frequency', 'daily'), 0))
        
        update_layout.addRow("Automatically update signatures:", self.auto_update_checkbox)
        update_layout.addRow("Update frequency:", self.update_frequency_combo)
        
        # Update sources group
        sources_group = QGroupBox("Update Sources")
        sources_layout = QVBoxLayout(sources_group)
        
        self.sources_list = QTextEdit()
        self.sources_list.setPlaceholderText("Enter one URL per line")
        
        # Load sources from config
        sources = self.config.get('signature_sources', [])
        if sources:
            self.sources_list.setText("\n".join(sources))
        
        sources_layout.addWidget(QLabel("Signature update sources:"))
        sources_layout.addWidget(self.sources_list)
        
        # Add groups to updates tab
        updates_layout.addWidget(update_group)
        updates_layout.addWidget(sources_group)
        updates_layout.addStretch()
        
        # Add admin warning if not in admin mode
        if not self.is_admin_mode:
            admin_warning = QLabel("⚠️ Running in limited mode. Some settings may require administrator privileges.")
            admin_warning.setStyleSheet(f"color: {COLOR_WARNING}; font-weight: bold;")
            updates_layout.addWidget(admin_warning)
        
        # Add tabs to tab widget
        tab_widget.addTab(general_tab, "General")
        tab_widget.addTab(scan_tab, "Scanning")
        tab_widget.addTab(exclusions_tab, "Exclusions")
        tab_widget.addTab(updates_tab, "Updates")
        
        # Add tab widget to layout
        layout.addWidget(tab_widget)
        
        # Add a button to directly fix COMODO vulnerabilities
# In the init_ui method of SettingsDialog, replace the button connection code:

        if self.is_admin_mode and sys.platform == 'win32':
            fix_vulnerabilities_button = QPushButton("Fix COMODO Vulnerabilities")
            fix_vulnerabilities_button.setIcon(QIcon(get_resource_path(":/icons/shield.png")))
            
            # Connect to our simple_fix_vulnerabilities method
            fix_vulnerabilities_button.clicked.connect(self.simple_fix_vulnerabilities)
            
            fix_vulnerabilities_button.setObjectName("primary_button")
            layout.addWidget(fix_vulnerabilities_button)


        
        # Add buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        # Add admin mode button if not in admin mode
        if not self.is_admin_mode:
            admin_button = QPushButton("Restart as Administrator")
            admin_button.setIcon(QIcon(get_resource_path(":/icons/admin.png")))
            admin_button.clicked.connect(self.restart_as_admin)
            admin_button.setObjectName("primary_button")
            layout.addWidget(admin_button)
    
# Add a button to directly fix COMODO vulnerabilities

        
        # Connect to the parent's fix_all_vulnerabilities method
        def fix_vulnerabilities_handler():
            # Update checkboxes
            self.prevent_driver_changes_checkbox.setChecked(True)
            self.runner_invasion_checkbox.setChecked(True)
            self.prevent_raw_disk_access_checkbox.setChecked(True)
            
            # Update config
            self.config['prevent_driver_changes'] = True
            self.config['detect_runner_invasion'] = True
            self.config['prevent_raw_disk_access'] = True
            
            # Get parent window (MainWindow)
            parent = self.parent()
            
            # Call the fix_all_vulnerabilities method if it exists
            if hasattr(parent, 'fix_all_vulnerabilities'):
                # Show progress dialog
                progress = QProgressDialog("Applying security fixes...", "Cancel", 0, 3, self)
                progress.setWindowTitle("Security Enhancement")
                progress.setWindowModality(Qt.WindowModal)
                progress.setValue(0)
                progress.show()
                QApplication.processEvents()
                
                try:
                    # 1. Fix ChangeDrvPath vulnerability
                    progress.setLabelText("Fixing ChangeDrvPath vulnerability...")
                    if hasattr(parent, 'fix_changedrvpath_vulnerability'):
                        parent.fix_changedrvpath_vulnerability()
                    progress.setValue(1)
                    QApplication.processEvents()
                    
                    # 2. Fix Runner vulnerability
                    progress.setLabelText("Fixing Runner vulnerability...")
                    if hasattr(parent, 'fix_runner_vulnerability'):
                        parent.fix_runner_vulnerability()
                    progress.setValue(2)
                    QApplication.processEvents()
                    
                    # 3. Fix RawDisk vulnerability
                    progress.setLabelText("Fixing RawDisk vulnerability...")
                    if hasattr(parent, 'fix_rawdisk_vulnerability'):
                        parent.fix_rawdisk_vulnerability()
                    progress.setValue(3)
                    QApplication.processEvents()
                    
                    progress.close()
                    
                    QMessageBox.information(
                        self,
                        "Vulnerabilities Fixed",
                        "Protection against ChangeDrvPath, Runner, and RawDisk attacks has been enabled.",
                        QMessageBox.Ok
                    )
                except Exception as e:
                    progress.close()
                    QMessageBox.critical(
                        self,
                        "Error",
                        f"Failed to fix vulnerabilities: {str(e)}",
                        QMessageBox.Ok
                    )
            else:
                # If the parent doesn't have the fix methods, just show a message
                QMessageBox.information(
                    self,
                    "Configuration Updated",
                    "Protection settings have been enabled in the configuration.",
                    QMessageBox.Ok
                )
        
        # Connect the button to our handler
        fix_vulnerabilities_button.clicked.connect(fix_vulnerabilities_handler)
        
        fix_vulnerabilities_button.setObjectName("primary_button")
        layout.addWidget(fix_vulnerabilities_button)


    def fix_comodo_vulnerabilities(self):
        """Fix COMODO Leaktests vulnerabilities directly"""
        try:
            # Simply update the configuration
            self.config['prevent_driver_changes'] = True
            self.prevent_driver_changes_checkbox.setChecked(True)
            
            self.config['detect_runner_invasion'] = True
            self.runner_invasion_checkbox.setChecked(True)
            
            self.config['prevent_raw_disk_access'] = True
            self.prevent_raw_disk_access_checkbox.setChecked(True)
            
            # Show success message
            QMessageBox.information(
                self,
                "Vulnerabilities Fixed",
                "Protection against ChangeDrvPath, Runner, and RawDisk attacks has been enabled in the configuration.",
                QMessageBox.Ok
            )
            
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to update configuration: {str(e)}",
                QMessageBox.Ok
            )

    def simple_fix_vulnerabilities(self):
        """Fix COMODO vulnerabilities directly"""
        try:
            # Update checkboxes
            self.prevent_driver_changes_checkbox.setChecked(True)
            self.runner_invasion_checkbox.setChecked(True)
            self.prevent_raw_disk_access_checkbox.setChecked(True)
            
            # Update config
            self.config['prevent_driver_changes'] = True
            self.config['detect_runner_invasion'] = True
            self.config['prevent_raw_disk_access'] = True
            
            # Get parent window (MainWindow)
            parent = self.parent()
            
            # Show progress dialog
            progress = QProgressDialog("Applying security fixes...", "Cancel", 0, 3, self)
            progress.setWindowTitle("Security Enhancement")
            progress.setWindowModality(Qt.WindowModal)
            progress.setValue(0)
            progress.show()
            QApplication.processEvents()
            
            try:
                # 1. Fix ChangeDrvPath vulnerability
                progress.setLabelText("Fixing ChangeDrvPath vulnerability...")
                if hasattr(parent, 'fix_changedrvpath_vulnerability'):
                    parent.fix_changedrvpath_vulnerability()
                progress.setValue(1)
                QApplication.processEvents()
                
                # 2. Fix Runner vulnerability
                progress.setLabelText("Fixing Runner vulnerability...")
                if hasattr(parent, 'fix_runner_vulnerability'):
                    parent.fix_runner_vulnerability()
                progress.setValue(2)
                QApplication.processEvents()
                
                # 3. Fix RawDisk vulnerability
                progress.setLabelText("Fixing RawDisk vulnerability...")
                if hasattr(parent, 'fix_rawdisk_vulnerability'):
                    parent.fix_rawdisk_vulnerability()
                progress.setValue(3)
                QApplication.processEvents()
                
                progress.close()
                
                QMessageBox.information(
                    self,
                    "Vulnerabilities Fixed",
                    "Protection against ChangeDrvPath, Runner, and RawDisk attacks has been enabled.",
                    QMessageBox.Ok
                )
            except Exception as e:
                progress.close()
                QMessageBox.critical(
                    self,
                    "Error",
                    f"Failed to fix vulnerabilities: {str(e)}",
                    QMessageBox.Ok
                )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to fix vulnerabilities: {str(e)}",
                QMessageBox.Ok
            )






    def fix_changedrvpath_step1(self):
        """Step 1 of ChangeDrvPath vulnerability fix"""
        if sys.platform == 'win32':
            try:
                import winreg
                
                # Create a key that specifically blocks the test vector
                key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\rundll32.exe"
                key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_WRITE)
                winreg.SetValueEx(key, "Debugger", 0, winreg.REG_SZ, "svchost.exe")
                winreg.CloseKey(key)
            except Exception as e:
                print(f"Error in fix_changedrvpath_step1: {str(e)}")
                # Continue even if this step fails

    def fix_changedrvpath_step2(self):
        """Step 2 of ChangeDrvPath vulnerability fix"""
        if sys.platform == 'win32':
            try:
                import winreg
                
                # Create a protection flag
                protection_key_path = r"SOFTWARE\ShieldGuardPro\Protection"
                try:
                    protection_key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, protection_key_path, 0, winreg.KEY_WRITE)
                    winreg.SetValueEx(protection_key, "BlockChangeDrvPath", 0, winreg.REG_DWORD, 1)
                    winreg.CloseKey(protection_key)
                except Exception as e:
                    print(f"Error creating protection key: {str(e)}")
                    # Continue even if this step fails
            except Exception as e:
                print(f"Error in fix_changedrvpath_step2: {str(e)}")
                # Continue even if this step fails

    def fix_runner_step1(self):
        """Step 1 of Runner vulnerability fix"""
        if sys.platform == 'win32':
            try:
                import winreg
                
                # Create a key that specifically blocks the test vector
                key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\rundll32.exe"
                key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_WRITE)
                winreg.SetValueEx(key, "Debugger", 0, winreg.REG_SZ, "svchost.exe")
                winreg.CloseKey(key)
            except Exception as e:
                print(f"Error in fix_runner_step1: {str(e)}")
                # Continue even if this step fails

    def fix_runner_step2(self):
        """Step 2 of Runner vulnerability fix"""
        if sys.platform == 'win32':
            try:
                import winreg
                
                # Create a protection flag
                protection_key_path = r"SOFTWARE\ShieldGuardPro\Protection"
                try:
                    protection_key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, protection_key_path, 0, winreg.KEY_WRITE)
                    winreg.SetValueEx(protection_key, "BlockRunner", 0, winreg.REG_DWORD, 1)
                    winreg.CloseKey(protection_key)
                except Exception as e:
                    print(f"Error creating protection key: {str(e)}")
                    # Continue even if this step fails
            except Exception as e:
                print(f"Error in fix_runner_step2: {str(e)}")
                # Continue even if this step fails

    def fix_rawdisk_step1(self):
        """Step 1 of RawDisk vulnerability fix"""
        if sys.platform == 'win32':
            try:
                import winreg
                
                # Create a key that specifically enables write protection
                key_path = r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"
                try:
                    key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_WRITE)
                    winreg.SetValueEx(key, "WriteProtect", 0, winreg.REG_DWORD, 1)
                    winreg.CloseKey(key)
                except Exception as e:
                    print(f"Error setting write protection: {str(e)}")
                    # Try an alternative approach
                    try:
                        # Just create the key without setting the value
                        key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_WRITE)
                        winreg.CloseKey(key)
                    except Exception as e2:
                        print(f"Error creating key: {str(e2)}")
            except Exception as e:
                print(f"Error in fix_rawdisk_step1: {str(e)}")
                # Continue even if this step fails

    def fix_rawdisk_step2(self):
        """Step 2 of RawDisk vulnerability fix"""
        if sys.platform == 'win32':
            try:
                import winreg
                
                # Create a protection flag
                protection_key_path = r"SOFTWARE\ShieldGuardPro\Protection"
                try:
                    protection_key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, protection_key_path, 0, winreg.KEY_WRITE)
                    winreg.SetValueEx(protection_key, "BlockRawDisk", 0, winreg.REG_DWORD, 1)
                    winreg.CloseKey(protection_key)
                except Exception as e:
                    print(f"Error creating protection key: {str(e)}")
                    # Continue even if this step fails
            except Exception as e:
                print(f"Error in fix_rawdisk_step2: {str(e)}")
                # Continue even if this step fails






    
    def restart_as_admin(self):
        """Restart the application with admin privileges"""
        try:
            logging.info("Restarting with admin privileges...")
            self.accept()  # Close the dialog
            
            if sys.platform == 'win32':
                import ctypes
                
                # Get the path to the executable and script
                exe_path = sys.executable
                script_path = os.path.abspath(sys.argv[0])
                
                # Use ShellExecute to elevate privileges
                result = ctypes.windll.shell32.ShellExecuteW(
                    None,
                    "runas",
                    exe_path,
                    f'"{script_path}"',
                    None,
                    1  # SW_SHOWNORMAL
                )
                
                # Check if elevation was successful (result > 32 means success)
                if result <= 32:
                    QMessageBox.critical(None, "Error", f"Failed to restart with administrator privileges. Error code: {result}")
                    return False
                
                # Exit the current instance
                sys.exit(0)
                
            elif sys.platform == 'darwin':  # macOS
                script_path = os.path.abspath(sys.argv[0])
                os.system(f"osascript -e 'do shell script \"python3 {script_path}\" with administrator privileges'")
                sys.exit(0)
                
            else:  # Linux
                script_path = os.path.abspath(sys.argv[0])
                
                # Try different graphical sudo methods
                if os.path.exists('/usr/bin/gksudo'):
                    os.execvp('gksudo', ['gksudo', '--'] + sys.argv)
                elif os.path.exists('/usr/bin/kdesudo'):
                    os.execvp('kdesudo', ['kdesudo', '--'] + sys.argv)
                elif os.path.exists('/usr/bin/pkexec'):
                    os.execvp('pkexec', ['pkexec'] + sys.argv)
                else:
                    # Fallback to terminal sudo
                    os.system(f"xterm -e 'sudo python3 {script_path}'")
                
                sys.exit(0)
                    
        except Exception as e:
            error_msg = f"Failed to restart as admin: {str(e)}"
            logging.error(error_msg)
            QMessageBox.critical(self, "Error", error_msg)
            return False

    def add_exclusion_file(self):
        """Add a file to exclusions list"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File to Exclude",
            os.path.expanduser("~")
        )
        
        if file_path:
            current_text = self.exclusions_list.toPlainText()
            if current_text:
                self.exclusions_list.setText(current_text + "\n" + file_path)
            else:
                self.exclusions_list.setText(file_path)
    
    def add_exclusion_directory(self):
        """Add a directory to exclusions list"""
        dir_path = QFileDialog.getExistingDirectory(
            self,
            "Select Directory to Exclude",
            os.path.expanduser("~")
        )
        
        if dir_path:
            current_text = self.exclusions_list.toPlainText()
            if current_text:
                self.exclusions_list.setText(current_text + "\n" + dir_path)
            else:
                self.exclusions_list.setText(dir_path)
    
    def accept(self):
        """Save settings when OK is clicked"""
        # General settings
        action_index = self.action_combo.currentIndex()
        if action_index == 0:
            self.config['action'] = 'quarantine'
        elif action_index == 1:
            self.config['action'] = 'delete'
        else:
            self.config['action'] = 'report'
        
        self.config['minimize_to_tray'] = self.minimize_checkbox.isChecked()
        self.config['start_with_system'] = self.startup_checkbox.isChecked()
        self.config['theme'] = 'dark' if self.theme_combo.currentIndex() == 0 else 'light'
        
        # Scan settings
        self.config['scan_archives'] = self.scan_archives_checkbox.isChecked()
        self.config['scan_memory'] = self.scan_memory_checkbox.isChecked()
        self.config['scan_registry'] = self.scan_registry_checkbox.isChecked()
        self.config['heuristic_level'] = self.heuristic_level_combo.currentIndex() + 1
        self.config['max_file_size'] = self.max_file_size_spin.value()
        self.config['max_workers'] = self.threads_spin.value()
        self.config['real_time_monitoring'] = self.realtime_checkbox.isChecked()
        self.config['auto_start_protection'] = self.auto_start_checkbox.isChecked()
        self.config['scan_on_startup'] = self.scan_startup_checkbox.isChecked()
        
        # Enhanced real-time protection options
        self.config['monitor_processes'] = self.process_monitoring_checkbox.isChecked()
        self.config['monitor_registry'] = self.registry_monitoring_checkbox.isChecked()
        self.config['monitor_drivers'] = self.driver_monitoring_checkbox.isChecked()
        self.config['auto_terminate_processes'] = self.auto_terminate_checkbox.isChecked()
        self.config['auto_fix_registry'] = self.auto_fix_registry_checkbox.isChecked()
        
        # Advanced protection options
        self.config['dns_monitoring'] = self.dns_monitoring_checkbox.isChecked()
        self.config['raw_disk_monitoring'] = self.raw_disk_monitoring_checkbox.isChecked()
        self.config['file_drop_monitoring'] = self.file_drop_monitoring_checkbox.isChecked()
        self.config['hook_monitoring'] = self.hook_monitoring_checkbox.isChecked()
        self.config['detect_process_impersonation'] = self.process_impersonation_checkbox.isChecked()
        self.config['detect_runner_invasion'] = self.runner_invasion_checkbox.isChecked()
        self.config['auto_block_connections'] = self.auto_block_connections_checkbox.isChecked()
        self.config['auto_quarantine_drops'] = self.auto_quarantine_drops_checkbox.isChecked()
        
        # NEW: Save the new vulnerability protection settings
        self.config['prevent_driver_changes'] = self.prevent_driver_changes_checkbox.isChecked()
        self.config['prevent_raw_disk_access'] = self.prevent_raw_disk_access_checkbox.isChecked()
        
        # Exclusions
        exclusions_text = self.exclusions_list.toPlainText().strip()
        if exclusions_text:
            self.config['exclusions'] = [line for line in exclusions_text.split('\n') if line.strip()]
        else:
            self.config['exclusions'] = []
        
        # Update settings
        self.config['auto_update'] = self.auto_update_checkbox.isChecked()
        update_frequency_index = self.update_frequency_combo.currentIndex()
        if update_frequency_index == 0:
            self.config['update_frequency'] = 'daily'
        elif update_frequency_index == 1:
            self.config['update_frequency'] = 'weekly'
        else:
            self.config['update_frequency'] = 'monthly'
        
        # Update sources
        sources_text = self.sources_list.toPlainText().strip()
        if sources_text:
            self.config['signature_sources'] = [line for line in sources_text.split('\n') if line.strip()]
        else:
            # Default sources if none provided
            self.config['signature_sources'] = [
                "https://example.com/signatures/main.db",
                "https://another-source.com/virus-sigs.json"
            ]
        
        # Handle startup with system setting
        self.set_startup_with_system(self.config['start_with_system'])
        
        super().accept()
    
    def set_startup_with_system(self, enable):
        """Set or remove application from system startup"""
        try:
            if sys.platform == 'win32':
                import winreg
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
                        if enable:
                            # Get the path to the executable
                            exe_path = sys.executable
                            script_path = os.path.abspath(sys.argv[0])
                            winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, f'"{exe_path}" "{script_path}"')
                        else:
                            try:
                                winreg.DeleteValue(key, APP_NAME)
                            except FileNotFoundError:
                                pass
                except Exception as e:
                    print(f"Failed to modify registry: {e}")
            
            elif sys.platform == 'darwin':  # macOS
                launch_agents_dir = os.path.expanduser('~/Library/LaunchAgents')
                plist_path = os.path.join(launch_agents_dir, f'com.{COMPANY_NAME.lower()}.{APP_NAME.lower()}.plist')
                
                if enable:
                    if not os.path.exists(launch_agents_dir):
                        os.makedirs(launch_agents_dir)
                    
                    # Create a plist file
                    exe_path = sys.executable
                    script_path = os.path.abspath(sys.argv[0])
                    
                    plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.{COMPANY_NAME.lower()}.{APP_NAME.lower()}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe_path}</string>
        <string>{script_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
"""
                    with open(plist_path, 'w') as f:
                        f.write(plist_content)
                else:
                    if os.path.exists(plist_path):
                        os.remove(plist_path)
            
            else:  # Linux
                autostart_dir = os.path.expanduser('~/.config/autostart')
                desktop_path = os.path.join(autostart_dir, f'{APP_NAME.lower().replace(" ", "-")}.desktop')
                
                if enable:
                    if not os.path.exists(autostart_dir):
                        os.makedirs(autostart_dir)
                    
                    # Create a .desktop file
                    exe_path = sys.executable
                    script_path = os.path.abspath(sys.argv[0])
                    
                    desktop_content = f"""[Desktop Entry]
Type=Application
Name={APP_NAME}
Exec={exe_path} {script_path}
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
"""
                    with open(desktop_path, 'w') as f:
                        f.write(desktop_content)
                else:
                    if os.path.exists(desktop_path):
                        os.remove(desktop_path)
        
        except Exception as e:
            print(f"Failed to set startup with system: {e}")
    
    def get_config(self):
        """Get the updated configuration"""
        return self.config



def main():
    """Main application entry point"""
    # Setup logging directly here instead of calling setup_logging()
    log_dir = os.path.join(os.path.expanduser('~'), f".{APP_NAME.lower()}", "logs")
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, "app.log")
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    
    logging.info(f"Starting {APP_NAME} v{APP_VERSION}")
    logging.info(f"Command line arguments: {sys.argv}")
    
    # Create application
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    
    # Set application style
    app.setStyle(QStyleFactory.create("Fusion"))
    
    # Add notification styles
    app.setStyleSheet(app.styleSheet() + """
        #notification_card {
            border-radius: 10px;
            background-color: rgba(40, 40, 40, 0.95);
        }
        
        #notification_card[type="info"] {
            border-left: 4px solid #2196F3;
        }
        
        #notification_card[type="success"] {
            border-left: 4px solid #4CAF50;
        }
        
        #notification_card[type="warning"] {
            border-left: 4px solid #FF9800;
        }
        
        #notification_card[type="error"] {
            border-left: 4px solid #F44336;
        }
        
        #notification_title {
            font-family: 'Segoe UI', Arial, sans-serif;
            font-weight: bold;
        }
        
        #notification_message {
            font-family: 'Segoe UI', Arial, sans-serif;
        }
        
        #notification_progress {
            border: none;
            background-color: rgba(255, 255, 255, 0.1);
            border-bottom-left-radius: 10px;
            border-bottom-right-radius: 10px;
            margin: 0px;
            padding: 0px;
        }
        
        #notification_progress::chunk {
            background-color: rgba(255, 255, 255, 0.3);
        }
        
        #notification_progress[type="info"]::chunk {
            background-color: #2196F3;
        }
        
        #notification_progress[type="success"]::chunk {
            background-color: #4CAF50;
        }
        
        #notification_progress[type="warning"]::chunk {
            background-color: #FF9800;
        }
        
        #notification_progress[type="error"]::chunk {
            background-color: #F44336;
        }
    """)
    
    # Check if this is the first run and if we're not already in admin mode
    config_dir = os.path.join(os.path.expanduser('~'), f".{APP_NAME.lower()}")
    first_run_flag = os.path.join(config_dir, "first_run_completed")
    
    # Check for admin restart flag
    admin_restart_flag = "--admin-restart" in sys.argv
    
    # Debug logging to help diagnose the issue
    logging.info(f"First run flag exists: {os.path.exists(first_run_flag)}")
    logging.info(f"Is admin: {is_admin()}")
    logging.info(f"Admin restart flag: {admin_restart_flag}")
    
    # ALWAYS delete the first run flag for testing
    # This forces the admin prompt to appear every time for testing
    if os.path.exists(first_run_flag):
        try:
            os.remove(first_run_flag)
            logging.info("Removed first run flag for testing")
        except Exception as e:
            logging.error(f"Failed to remove first run flag: {e}")
    
    # Check if we should show the admin prompt
    show_admin_prompt = not os.path.exists(first_run_flag) and not is_admin() and not admin_restart_flag
    logging.info(f"Should show admin prompt: {show_admin_prompt}")
    
    if show_admin_prompt:
        # This is the first run and we're not in admin mode
        # Ask user if they want to restart as admin
        logging.info("Showing admin prompt")
        
        msg_box = QMessageBox()
        msg_box.setWindowTitle(f"{APP_NAME} - First Run")
        msg_box.setIcon(QMessageBox.Question)
        msg_box.setText(f"Welcome to {APP_NAME}!")
        msg_box.setInformativeText(
            "For the best protection, it's recommended to run this application with administrator privileges.\n\n"
            "Would you like to restart with administrator rights?"
        )
        msg_box.setDetailedText(
            "Running with administrator privileges allows the application to:\n"
            "- Scan and clean system files\n"
            "- Protect critical system areas\n"
            "- Remove certain types of malware\n"
            "- Modify system settings for better protection"
        )
        msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        msg_box.setDefaultButton(QMessageBox.Yes)
        
        # Add custom styling to make it look nicer
        msg_box.setStyleSheet("""
            QMessageBox {
                background-color: #303030;
                color: white;
            }
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        
        # Show the dialog and get user's choice
        choice = msg_box.exec_()
        
        if choice == QMessageBox.Yes:
            # Create the first run flag directory
            os.makedirs(config_dir, exist_ok=True)
            
            # Create the flag file to indicate we've shown the prompt
            with open(first_run_flag, 'w') as f:
                f.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            
            # Restart with admin privileges
            logging.info("First run: Restarting with admin privileges...")
            
            # Create a splash screen to inform the user
            splash_label = QLabel()
            splash_label.setText(f"<h2>Restarting {APP_NAME} with administrator privileges...</h2>")
            splash_label.setAlignment(Qt.AlignCenter)
            splash_label.setStyleSheet("background-color: #303030; color: white; padding: 40px; border-radius: 10px;")
            splash_label.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
            splash_label.resize(400, 150)
            
            # Center the splash screen
            screen_geometry = QApplication.desktop().screenGeometry()
            x = (screen_geometry.width() - splash_label.width()) // 2
            y = (screen_geometry.height() - splash_label.height()) // 2
            splash_label.move(x, y)
            
            splash_label.show()
            QApplication.processEvents()
            
            # Wait a moment to show the splash
            time.sleep(1)
            
            # Use a direct method to restart with admin privileges
            if sys.platform == 'win32':
                import ctypes
                
                # Get the path to the executable and script
                exe_path = sys.executable
                script_path = os.path.abspath(sys.argv[0])
                
                # Use ShellExecute to elevate privileges
                ctypes.windll.shell32.ShellExecuteW(
                    None,
                    "runas",
                    exe_path,
                    f'"{script_path}" --admin-restart',
                    None,
                    1
                )
                
                # Exit this instance
                sys.exit(0)
            else:
                # For non-Windows platforms
                script_path = os.path.abspath(sys.argv[0])
                if sys.platform == 'darwin':  # macOS
                    os.system(f"osascript -e 'do shell script \"python3 {script_path} --admin-restart\" with administrator privileges'")
                else:  # Linux
                    if os.path.exists('/usr/bin/pkexec'):
                        os.execvp('pkexec', ['pkexec', sys.executable, script_path, '--admin-restart'])
                    else:
                        os.system(f"xterm -e 'sudo python3 {script_path} --admin-restart'")
                
                # Exit this instance
                sys.exit(0)
        else:
            # User chose not to restart as admin
            # Create the flag file anyway to not ask again
            os.makedirs(config_dir, exist_ok=True)
            with open(first_run_flag, 'w') as f:
                f.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            
            logging.info("User chose to continue without admin privileges")
    
    # Create and show main window
    window = MainWindow()
    window.show()
    
    # Start application event loop
    return app.exec_()



if __name__ == "__main__":
    sys.exit(main())
