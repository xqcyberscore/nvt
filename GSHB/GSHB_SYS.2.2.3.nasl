##############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_SYS.2.2.3.nasl 8179 2017-12-19 14:03:44Z emoss $
#
# IT-Grundschutz Baustein: SYS.2.2.3 Clients unter Windows 10
#
# Authors:
# Emanuel Moss <emanuel.moss@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109034");
  script_version("$Revision: 8179 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 15:03:44 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-12-13 07:42:28 +0200 (Wed, 13 Dec 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");  
  script_name('SYS.2.2.3 Clients unter Windows 10');
  script_xref(name : "URL" , value : " https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/bausteine/SYS/SYS_2_2_3_Clients_unter_Windows_10.html ");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB-ITG");
  script_dependencies("GSHB/GSHB_WMI_OSInfo.nasl", "GSHB_WMI_Antivir.nasl", "GSHB/GSHB_SMB_UAC_Config.nasl", "GSHB/GSHB_WMI_EFS.nasl");
  script_tag(name : "summary" , value : 'Ziel dieses Bausteins ist der Schutz von Informationen, 
      die durch und auf Windows 10-Clients verarbeiten werden.');
  
  exit(0);
}

include("smb_nt.inc");
include("misc_func.inc");

Windows_Version = get_kb_item("WMI/WMI_OSVER");
Windows_Name = get_kb_item("WMI/WMI_OSNAME");
Windows_Architecture = get_kb_item("WMI/WMI_OSArchitecture");

if( Windows_Version != "10.0" ||  "windows 10" >!< tolower(Windows_Name) ){
  set_kb_item(name:"GSHB/SYS.2.2.3", value:"error");
  log_message(data:"Auf dem Host scheint kein Microsft Windows 10 Betriebsystem installiert zu sein,
      oder es konnte keine Verbindung zum Host hergestellt werden.");
  exit(0);
}

host    = get_host_ip();
usrname = kb_smb_login(); 
domain  = kb_smb_domain();
if( domain ){
  usrname_handle = domain + '\\' + usrname;
  usrname_WmiCmd = domain + '/' + usrname;
}
passwd  = kb_smb_password();


# SYS.2.2.3.A1 Planung des Einsatzes von Cloud-Diensten
SYS_2_2_3_A1 = 'SYS.2.2.3.A1 Planung des Einsatzes von Cloud-Diensten:\n';
SYS_2_2_3_A1 += 'Diese Maßnahme kann nicht implementiert werden.\n\n';

# SYS.2.2.3.A2 Geeignete Auswahl einer Windows 10-Version und Beschaffung
SYS_2_2_3_A2 = 'SYS.2.2.3.A2 Geeignete Auswahl einer Windows 10-Version und Beschaffung:\n';
if( Windows_Architecture ){
  SYS_2_2_3_A2 += 'Windows 10 wird in einer ' + Windows_Architecture + ' Architektur betrieben.\n';
}else{
  SYS_2_2_3_A2 += 'Die Windows 10 Architektur (32 / 64 Bit) konnte nicht bestimmt werden.\n';
}
SYS_2_2_3_A2 += 'Der Host läuft mit folgendem Betriebssystem: ' + Windows_Name + '.\n\n';

# SYS.2.2.3.A3 Geeignetes Patch- und Änderungsmanagement
SYS_2_2_3_A3 = 'SYS.2.2.3.A3 Geeignetes Patch- und Änderungsmanagement:\n';
SYS_2_2_3_A3 += 'Diese Maßnahme kann nicht implementiert werden.\n\n';

# SYS.2.2.3.A4 Telemetrie und Datenschutzeinstellungen
SYS_2_2_3_A4 = 'SYS.2.2.3.A4 Telemetrie und Datenschutzeinstellungen:\n';
SYS_2_2_3_A4 += 'Diese Maßnahme kann nicht implementiert werden.\n\n';

# SYS.2.2.3.A5 Schutz vor Schadsoftware
SYS_2_2_3_A5 = 'SYS.2.2.3.A5 Schutz vor Schadsoftware:\n';
SecurityCenter2 = get_kb_item("WMI/Antivir/SecurityCenter2");
SecurityCenter2 = split(SecurityCenter2, keep:FALSE);
if( max_index(SecurityCenter2) <= 1 ){
  SYS_2_2_3_A5 += 'Es konnte kein Viren-Schutzprogramm im Security Center gefunden werden.\n';
  SYS_2_2_3_A5 += 'Stellen Sie sicher, dass gleich- oder höherwertige Maßnahmen zum Schutz des IT-Sytems vor einer Infektion mit Schadsoftware getroffen wurde.\n\n';
}else{
  SYS_2_2_3_A5 += 'Folgende Schutzprogramme sind installiert:\n';

  # get state of each AntiVir program (can be more than one)
  foreach line (SecurityCenter2){
    line = split(line, sep:'|', keep:FALSE);

    # skip header
    if( tolower(line[0]) == 'displayname' ){
      continue;
    }

    SYS_2_2_3_A5 += line[0] + '\n';
    ProductState = dec2hex(num:line[4]);

    ProtectionStatus = hexstr(substr( ProductState, 1, 1));
    if( ProtectionStatus == "00" || ProtectionStatus == "01" ){
      ProtectionStatus_Res = "nicht aktiv";
    }else if( ProtectionStatus == "10" || ProtectionStatus == "11"){
      ProtectionStatus_Res = "aktiv";
    }else{
      ProtectionStatus_Res = "unbekannt";
    }

    UpToDate = hexstr(substr(ProductState, 2, 2));
    if( UpToDate == "00" ){
      UpToDate_Res = "aktuell";
    }else if( UpToDate == "10" ){
      UpToDate_Res = "veraltet";
    }else{
      UpToDate_Res = "unbekannt";
    }

    SYS_2_2_3_A5 += 'Status: ' + ProtectionStatus_Res + '\n';
    SYS_2_2_3_A5 += 'Zeitstempel: ' + UpToDate_Res + '\n\n';
  }
}

# SYS.2.2.3.A6 Integration von Online-Konten in das Betriebssystem [Benutzer]
SYS_2_2_3_A6 = 'SYS.2.2.3.A6 Integration von Online-Konten in das Betriebssystem [Benutzer]:\n';
NoConnectedUser = registry_get_dword(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", item:"NoConnectedUser");
if( NoConnectedUser == "3" ){
  SYS_2_2_3_A6 += 'Benutzer können sich nicht mit Microsoft-Konten einloggen oder diese hinzufügen.\n';
}else if( NoConnectedUser == "2" ){
  SYS_2_2_3_A6 += 'Benutzer können sich nicht mit Microsoft-Konten einloggen, es können aber neue hinzugefügt werden. Dies muss deaktiviert sein.\n';
}else if( NoConnectedUser == "1" ){
  SYS_2_2_3_A6 += 'Benutzer können sich mit Microsoft-Konten einloggen, es können aber keine neue hinzugefügt werden. Dies muss deaktiviert sein.\n';
}else{
  SYS_2_2_3_A6 += 'Benutzer können sich mit Microsoft-Konten einloggen und diese hinzufügen. Dies muss deaktiviert sein.\n';
}

SwitchToMicrosoftAccount = registry_get_dword(key:"SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowYourAccount", value:"value");
if( SwitchToMicrosoftAccount == "0" ){
  SYS_2_2_3_A6 += 'Benutzer können ihr Konto nicht zu einem Microsoft-Konto ändern.\n';
}else{
  SYS_2_2_3_A6 += 'Benutzer können ihr Konto zu einem Microsoft-Konto ändern. Dies sollte deaktiviert werden.\n';
}

handle = wmi_connect(host:host, username:usrname_handle, password:passwd, ns:'root\\rsop\\computer');
query = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeDenyInteractiveLogonRight' AND precedence=1";
SeDenyInteractiveLogonRight = wmi_query(wmi_handle:handle, query:query);
if( ! SeDenyInteractiveLogonRight ){
  SYS_2_2_3_A6 += 'Es konnten keine Benutzer gefunden werden, denen die lokale Anmeldung verweigert wird (GPO "Lokale Anmeldung Verweigern").\n';
}else{
  SeDenyInteractiveLogonRight = split(SeDenyInteractiveLogonRight, keep:FALSE);
  SYS_2_2_3_A6 += 'Folgenden Benutzern wird die lokale Anmeldung verweigert (GPO "Lokale Anmeldung Verweigern"):\n';
  foreach line (SeDenyInteractiveLogonRight){
    line = split(line, sep:'|', keep:FALSE);
    if( tolower(line[0]) == 'accountlist' ){
      continue;
    }   

    for( y=0; y<=max_index(line)-3; y++ ){
      SYS_2_2_3_A6 += line[y];
      if( y == max_index(line)-3 ){
        SYS_2_2_3_A6 += '\n';
      }else{
        SYS_2_2_3_A6 += ', ';
      }   
    }   
  }
}

query = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeInteractiveLogonRight' AND precedence=1";
SeInteractiveLogonRight = wmi_query(wmi_handle:handle, query:query);
if( ! SeInteractiveLogonRight ){
  SYS_2_2_3_A6 += 'Es konnten keine Benutzer gefunden werden, denen die lokale Anmeldung zugelassen wird (GPO "Lokale Anmeldung Zulassen").\n\n';
}else{
  SeInteractiveLogonRight = split(SeInteractiveLogonRight, keep:FALSE);
  SYS_2_2_3_A6 += 'Folgenden Benutzern wird die lokale Anmeldung zugelassen (GPO "Lokale Anmeldung Zulassen"):\n';
  foreach line (SeInteractiveLogonRight){
    line = split(line, sep:'|', keep:FALSE);
    if( tolower(line[0]) == 'accountlist' ){
      continue;
    }   

    for( y=0; y<=max_index(line)-3; y++ ){
      SYS_2_2_3_A6 += line[y];
      if( y == max_index(line)-3 ){
        SYS_2_2_3_A6 += '\n\n';
      }else{
        SYS_2_2_3_A6 += ', ';
      }   
    }   
  }
}


# SYS.2.2.3.A7 Lokale Sicherheitsrichtlinien
SYS_2_2_3_A7 = 'SYS.2.2.3.A7 Lokale Sicherheitsrichtlinien:\n';
SYS_2_2_3_A7 += 'Diese Maßnahme kann nicht implementiert werden.\n\n';

# SYS.2.2.3.A8 Zentrale Verwaltung der Sicherheitsrichtlinien von Clients
SYS_2_2_3_A8 = 'SYS.2.2.3.A8 Zentrale Verwaltung der Sicherheitsrichtlinien von Clients:\n';
SYS_2_2_3_A8 += 'Diese Maßnahme kann nicht implementiert werden.\n\n';

# SYS.2.2.3.A9 Sichere zentrale Authentisierung der Windows-Clients
SYS_2_2_3_A9 = 'SYS.2.2.3.A9 Sichere zentrale Authentisierung der Windows-Clients:\n';
SYS_2_2_3_A9 += 'Diese Maßnahme kann nicht implementiert werden.\n\n';

# SYS.2.2.3.A10 Konfiguration zum Schutz von Anwendungen in Windows 10
SYS_2_2_3_A10 = 'SYS.2.2.3.A10 Konfiguration zum Schutz von Anwendungen in Windows 10:\n';
res = win_cmd_exec(cmd:"bcdedit /enum", password:passwd, username:usrname_WmiCmd);
if( res ){
  res = split(res, keep:FALSE);
  foreach line ( res ){
    nx_status = eregmatch(string:line, pattern:"nx[ ]+([a-z,A-Z]+)");
    if( nx_status[1] ){
      DEP = nx_status[1];
      break;
    }
  }
}

if( DEP ){
  SYS_2_2_3_A10 += 'Die Dateiausführungsverhinderung ist in Einstellung: ' + DEP + '.';
  if( tolower(DEP) != "optout" ){
    SYS_2_2_3_A10 += ' Dies sollte auf die Einstellung "OptOut" geändert werden.';
  }
  SYS_2_2_3_A10 += '\n\n';
}else{
  SYS_2_2_3_A10 += 'Die Einstellung der Dateiausführungsverhinderung konnte nicht bestimmt werden.\n\n';
}


# SYS.2.2.3.A11 Schutz der Anmeldeinformationen in Windows 10
SYS_2_2_3_A11 = 'SYS.2.2.3.A11 Schutz der Anmeldeinformationen in Windows 10:\n';
if( "enterprise" >< tolower(Windows_Name) ){
  VBS = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard", item:"EnableVirtualizationBasedSecurity");
  RequirePlatformSecFeatures = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard", item:"RequirePlatformSecurityFeatures");
  HypervisorEnforcedCodeIntegrity = registry_get_dword(key:"keySOFTWARE\Policies\Microsoft\Windows\DeviceGuard", item:"HypervisorEnforcedCodeIntegrity");
  HVCIMATRequired = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard", item:"HVCIMATRequired");
  LsaCfgFlags = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard", item:"LsaCfgFlags");

  if( VBS == "1" ){
    SYS_2_2_3_A11 += 'Virtualization Based Security (VBS) ist aktiviert.\n';
  }else{
    SYS_2_2_3_A11 += 'Virtualization Based Security (VBS) ist nicht aktiviert.\n';
    SYS_2_2_3_A11 += 'Dies sollte aktiviert werden, um den Virtual Security Mode zu aktivieren.\n';
  }

  if( RequirePlatformSecFeatures == "3" ){
    SYS_2_2_3_A11 += 'VBS ist mit Direct-Memory-Access-Schutz aktiviert.\n';
  }else if( RequirePlatformSecFeatures == "1" ){
    SYS_2_2_3_A11 += 'VBS ist ohne Direct-Memory-Access-Schutz aktiviert.\n';
  }

  if( HypervisorEnforcedCodeIntegrity == "0" ){
    SYS_2_2_3_A11 += '"Virtualization Based Protection of Code Integrity" ist nicht aktiviert.\n';
  }else if( HypervisorEnforcedCodeIntegrity == "1" ){
    SYS_2_2_3_A11 += '"Virtualization Based Protection of Code Integrity" ist mit UEFI Sperre aktiviert.\n';
  }else if( HypervisorEnforcedCodeIntegrity == "2" ){
    SYS_2_2_3_A11 += '"Virtualization Based Protection of Code Integrity" ist ohne UEFI Sperre aktiviert.\n';
  }else if( HypervisorEnforcedCodeIntegrity == "3" ){
    SYS_2_2_3_A11 += '"Virtualization Based Protection of Code Integrity" ist nicht konfiguriert.\n';
  }

  if( HVCIMATRequired == "1" ){
    SYS_2_2_3_A11 += 'Die Option "Require UEFI Memory Attributes Table" ist aktiviert.\n';
  }else if( HVCIMATRequired == "0" ){
    SYS_2_2_3_A11 += 'Die Option "Require UEFI Memory Attributes Table" ist nicht aktiviert. Dies kann dazu führen,\n';
    SYS_2_2_3_A11 += 'dass inkompatible Geräte einen Absturz des Systems verursachen. Diese Option sollte daher aktiviert werden.\n';
  }

  if( LsaCfgFlags == "0" ){
    LSASS = registry_get_dword(key:"SYSTEM\CurrentControlSet\Control\Lsa", item:"RunAsPPL");
    if( LSASS == "1" ){
      SYS_2_2_3_A11 += 'Credential Guard ist nicht aktiviert, jedoch ist PPL aktiviert. Es sollte überlegt werden, Credential Guard einzusetzen.\n';
    }else{
      SYS_2_2_3_A11 += 'Credential Guard ist nicht aktiviert. Dies sollte aktiviert werden, da PPL ebenfalls nicht aktiviert ist.\n';
    }
  }else if( LsaCfgFlags == "1" ){
    SYS_2_2_3_A11 += 'Credential Guard ist mit UEFI Sperre aktiviert.\n';
  }else if( LsaCfgFlags == "2" ){
    SYS_2_2_3_A11 += 'Credential Guard ist ohne UEFI Sperre aktiviert.\n';
  }else if( LsaCfgFlags == "3" ){
    LSASS = registry_get_dword(key:"SYSTEM\CurrentControlSet\Control\Lsa", item:"RunAsPPL");
    if( LSASS == "1" ){
      SYS_2_2_3_A11 += 'Credential Guard ist nicht aktiviert, jedoch ist PPL aktiviert. Es sollte überlegt werden, Credential Guard einzusetzen.\n';
    }else{
      SYS_2_2_3_A11 += 'Credential Guard ist nicht aktiviert. Dies sollte aktiviert werden, da PPL ebenfalls nicht aktiviert ist.\n';
    }
  }

  SYS_2_2_3_A11 += '\n';
}else{
  SYS_2_2_3_A11 += 'Diese Maßnahme kann nicht überprüft werden, da es keine Enterprise Version installiert ist.\n\n';
}


# SYS.2.2.3.A12 Datei- und Freigabeberechtigungen
SYS_2_2_3_A12 = 'SYS.2.2.3.A12 Datei- und Freigabeberechtigungen:\n';
SYS_2_2_3_A12 += 'Diese Maßnahme kann nicht implementiert werden.\n\n';

# SYS.2.2.3.A13 Einsatz der SmartScreen-Funktionen
SYS_2_2_3_A13 = 'SYS.2.2.3.A13 Einsatz der SmartScreen-Funktionen:\n';
SmartScreen = registry_get_dword(key:"Software\Policies\Microsoft\Windows\System", item:"EnableSmartScreen");
if( SmartScreen && SmartScreen != "0" ){
  SYS_2_2_3_A13 += 'Die SmartScreen-Funktion ist aktiviert. Diese sollte deaktiviert werden.\n\n';
}else{
  SYS_2_2_3_A13 += 'Die SmartScreen-Funktion ist deaktiviert.\n\n';
}


# SYS.2.2.3.A14 Einsatz des Sprachassistenten Cortana [Benutzer]
SYS_2_2_3_A14 = 'SYS.2.2.3.A14 Einsatz des Sprachassistenten Cortana:\n';
Cortana = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows\Windows Search", item:"AllowCortana");
if( Cortana == "0" ){
  SYS_2_2_3_A14 += 'Cortana ist deaktiviert.\n\n';
}else{
  SYS_2_2_3_A14 += 'Cortana ist aktiviert. Cortana sollte deaktiviert werden.\n\n';
}


# SYS.2.2.3.A15 Einsatz der Synchronisationsmechanismen in Windows 10
SYS_2_2_3_A15 = 'SYS.2.2.3.A15 Einsatz der Synchronisationsmechanismen in Windows 10:\n';
DisableSettingSync = registry_get_dword(key:"Software\Policies\Microsoft\Windows\SettingSync", item:"DisableSettingSync");
if( DisableSettingSync == '2' ){
  SYS_2_2_3_A15 += 'Einstellungen werden nicht synchronisiert.\n';
}else{
  SYS_2_2_3_A15 += 'Synchronisation der Einstellungen werden nicht unterbunden. ';
  SYS_2_2_3_A15 += 'Dies sollte verhindert werden (GPO: "Synchronisation verhindern")\n';
}

ConnectedSearchUseWeb = registry_get_dword(key:"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ConnectedSearch", item:"ConnectedSearchUseWeb");
if( ConnectedSearchUseWeb == '0' ){
  SYS_2_2_3_A15 += 'Bei einer Suche mit Bing werden keine Internetsuchvorschläge einbezogen.\n';
}else{
  SYS_2_2_3_A15 += 'Bei einer Suche mit Bing werden Internetsuchvorschläge einbezogen. ';
  SYS_2_2_3_A15 += 'Dies sollte verhindert werden (GPO: "Nicht im Web suchen und keine Webergebnisse anzeigen").\n';
}

ConnectedSearchPrivacy = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows\Windows Search", item:"ConnectedSearchPrivacy");
if( ConnectedSearchPrivacy == '2' ){
  SYS_2_2_3_A15 += 'Bei einer Suche mit Bing werden lediglich Anwendungsinformationen anonymisiert übertragen.\n';
}else{
  SYS_2_2_3_A15 += 'Bei einer Suche mit Bing werden Nutzerdaten übertragen. ';
  SYS_2_2_3_A15 += 'Dies sollte verhindert werden (GPO: "Festlegen der in der Suche freizugebenden Informationen")\n';
}

DisableFileSync = registry_get_dword(key:"Software\Policies\Microsoft\Windows\Skydrive", item:"DisableFileSync");
if( DisableFileSync == '1' ){
  SYS_2_2_3_A15 += 'OneDrive ist als Speicherort für Dateien deaktiviert.\n';
}else{
  SYS_2_2_3_A15 += 'OneDrive wird als Speicherort für Dateien nicht verhindert. ';
  SYS_2_2_3_A15 += 'Dies sollte verhindert werden (GPO: "verwendung von OneDrive für die Datenspeicherung verhindern")\n';
}

DisableLibrariesDefaultSaveToSkyDrive = registry_get_dword(key:"Software\Policies\Microsoft\Windows\Skydrive", item:"DisableLibrariesDefaultSaveToSkyDrive");
if( DisableLibrariesDefaultSaveToSkyDrive == '1' ){
  SYS_2_2_3_A15 += 'Dateien und Dokumente werden standardmäßig nicht auf OneDrive gespeichert.\n';
}else{
  SYS_2_2_3_A15 += 'Dateien und Dokumente werden standardmäßig auf OneDrive gespeichert. ';
  SYS_2_2_3_A15 += 'Dies sollte verhindert werden (GPO: "Dokumente standardmäßig auf OneDrive speichern")\n';
}

WiFiSense = registry_get_dword(key:"Software\Microsoft\wcmsvc\wifinetworkmanager\config", item:"AutoConnectAllowedOEM");
if( WiFiSense == "0" ){
  SYS_2_2_3_A15 += 'Das Sharing von WLAN-Passwörtern ist deaktiviert.\n\n';
}else{
  SYS_2_2_3_A15 += 'Das Sharing von WLAN-Passwörtern ist aktiviert oder kann von Benutzern aktiviert werden. ';
  SYS_2_2_3_A15 += 'Dies sollte deaktiviert werden.\n\n';
}


# SYS.2.2.3.A16 Anbindung von Windows 10 an den Windows Store
SYS_2_2_3_A16 = 'SYS.2.2.3.A16 Anbindung von Windows 10 an den Windows Store:\n';
WindowsStore = registry_get_dword(key:"Software\Policies\Microsoft\WindowsStore", item:"RemoveWindowsStore");
if( WindowsStore == "1" ){
  SYS_2_2_3_A16 += 'Der Windows Store ist deaktiviert.\n\n';
}else{
  SYS_2_2_3_A16 += 'Der Windows Store ist nicht deaktiviert. Dieser sollte, falls nicht benötigt, deaktiviert werden.\n\n';
}


# SYS.2.2.3.A17 Verwendung der automatischen Anmeldung
SYS_2_2_3_A17 = 'SYS.2.2.3.A17 Verwendung der automatischen Anmeldung:\n';
SYS_2_2_3_A17 += 'Diese Maßnahme kann nicht implementiert werden.\n\n';

# SYS.2.2.3.A18 Einsatz der Windows-Remoteunterstützung
SYS_2_2_3_A18 = 'SYS.2.2.3.A18 Einsatz der Windows-Remoteunterstützung:\n';

OfferRemoteAssistance = registry_get_dword(key:"Software\policies\Microsoft\Windows NT\Terminal Services", item:"fAllowUnsolicited");
if( OfferRemoteAssistance == "0" ){
  SYS_2_2_3_A18 += 'Remote-Unterstützung anbieten ist deaktiviert. ';
  SYS_2_2_3_A18 += 'Eine Remote-Unterstützung kann nur nach einer expliziten Einladung erfolgen.\n';
}else{
  SYS_2_2_3_A18 += 'Remote-Unterstützung anbieten ist nicht deaktiviert. Dies sollte deaktiviert sein, damit eine ';
  SYS_2_2_3_A18 += 'Remote-Unterstützung nur nach einer expliziten Einladung erfolgen kann.\n';
}

UsersPermission = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", item:"Shadow");
if( UsersPermission == "0" ){
  SYS_2_2_3_A18 += 'Die Remote-Kontrolle ist deaktiviert.\n';
}else if( UsersPermission == "1" ){
  SYS_2_2_3_A18 += 'Eine Remote-Kontrolle bedarf der Zustimmung des Benutzers. Es kann die volle Kontrolle übernommen werden.\n';
}else if( UsersPermission == "2" ){
  SYS_2_2_3_A18 += 'Eine vollständige Remote-Kontrolle kann ohne Zustimmung des Benutzers erfolgen. Dies sollte deaktiviert werden.\n';
}else if( UsersPermission == "3" ){
  SYS_2_2_3_A18 += 'Eine Remote-Kontrolle bedarf der Zustimmung des Benutzers. Es kann die Session des Benutzers beobachtet werden.\n';
}else if( UsersPermission == "4" ){
  SYS_2_2_3_A18 += 'Die Session kann ohne Zustimmung des Benutzers beobachtet werden. Dies sollte deaktiviert werden.\n';
}else{
  SYS_2_2_3_A18 += 'Die Einstellungen für Remotedesktopdienste konnte nicht ausgelesen werden.\n';
}

MaxTicketExpiry = registry_get_dword(key:"Software\policies\Microsoft\Windows NT\Terminal Services", item:"MaxTicketExpiry");
MaxTicketExpiryUnits = registry_get_dword(key:"Software\policies\Microsoft\Windows NT\Terminal Services", item:"MaxTicketExpiryUnits");
if( MaxTicketExpiryUnits == "0" ){
  Unit = " Minuten.";
}else if( MaxTicketExpiryUnits == "1" ){
  Unit = " Stunden.";
}else if( MaxTicketExpiryUnits == "2" ){
  Unit = " Tage.";
}

if( MaxTicketExpiry && Unit ){
  SYS_2_2_3_A18 += 'Die maximale Gültigkeitsdauer der Einladung beträgt ' + MaxTicketExpiry + MaxTicketExpiryUnits + '\n\n';
}else{
  SYS_2_2_3_A18 += 'Es ist keine maximale Gültigkeitsdauer der Einladung konfiguriert. Diese sollte eine angemessene Größe haben.\n\n';
}


# SYS.2.2.3.A19 Verwendung des Fernzugriffs über RDP [Benutzer]
SYS_2_2_3_A19 += 'SYS.2.2.3.A19 Verwendung des Fernzugriffs über RDP:\n';
RDP_User = win_cmd_exec(cmd:'net localgroup "Remote Desktop Users"', password:passwd, username:usrname_WmiCmd);
Administrators = win_cmd_exec(cmd:'net localgroup "Administrators"', password:passwd, username:usrname_WmiCmd);

if( ! RDP_User ){
  SYS_2_2_3_A19 += 'Die Mitglieder der Gruppe "Remote Desktop Users" konnten nicht ausgelesen werden.\n';
}else if( "is not recognized as an internal or external command" >< RDP_User ){
  SYS_2_2_3_A19 += 'Die Mitglieder der Gruppe "Remote Desktop Users" konnten nicht ausgelesen werden.\n';
}else{
  SYS_2_2_3_A19 += 'Folgende Benutzer sind Mitglieder der Gruppe "Remote Desktop Users":\n';
  RDP_User = split(RDP_User, keep:FALSE);
  foreach line (RDP_User){
    if( ereg(string:line, pattern:"^impacket", icase:TRUE) ){
      continue;
    }
    if( ereg(string:line, pattern:"^\[\*\]") ){
      continue;
    }
    SYS_2_2_3_A19 += line + '\n';;
  }
  SYS_2_2_3_A19 += '\n';
}

if( ! Administrators ){
  SYS_2_2_3_A19 += 'Die Mitglieder der Gruppe "Administrators" konnten nicht ausgelesen werden.\n';
}else if( "is not recognized as an internal or external command" >< Administrators ){
  SYS_2_2_3_A19 += 'Die Mitglieder der Gruppe "Administrators" konnten nicht ausgelesen werden.\n';
}else{
  SYS_2_2_3_A19 += 'Folgende Benutzer sind Mitglieder der Gruppe "Administrators" und haben somit einen Remote-Desktopzugriff:\n';
  Administrators = split(Administrators, keep:FALSE);
  foreach line (Administrators){
    if( ereg(string:line, pattern:"^impacket", icase:TRUE) ){
      continue;
    }
    if( ereg(string:line, pattern:"^\[\*\]") ){
      continue;
    }
    SYS_2_2_3_A19 += line + '\n';
  }
}

DisableClipboard = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", item:"fDisableClip");
DisablePrinters = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", item:"fForceClientLptDef");
DisableLocalPrint = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", item:"fDisableCpm");
DisableCOM = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", item:"fDisableCcm");
DisableLPT = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", item:"fDisableLPT");
DisableDrive = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", item:"fDisableCdm");
DisableSmartCard = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", item:"fEnableSmartCard");
DisablePlugAndPlay = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", item:"fDisablePNPRedir");

if( DisableClipboard == "1" ){
  SYS_2_2_3_A19 += 'Benutzer können die Zwischenablage nicht verwenden.\n';
}else{
  SYS_2_2_3_A19 += 'Benutzer können die Zwischenablage verwenden.\n';
}

if( DisablePrinters == "1" ){
  SYS_2_2_3_A19 += 'Der Standarddrucker des Remote-Hosts wird nicht als Drucker verwendet.\n';
}else{
  SYS_2_2_3_A19 += 'Der Standarddrucker des Remote-Hosts wird als Drucker verwendet.\n';
}

if( DisableLocalPrint == "1" ){
  SYS_2_2_3_A19 += 'Benutzer können keine Druckaufträge vom Remote-Host an einen lokalen Drucker senden.\n';
}else{
  SYS_2_2_3_A19 += 'Benutzer können Druckaufträge vom Remote-Host an einen lokalen Drucker senden.\n';
}

if( DisableCOM == "1" ){
  SYS_2_2_3_A19 += 'Benutzer können keine Daten an den lokalen COM-Port senden.\n';
}else{
  SYS_2_2_3_A19 += 'Benutzer können Daten an den lokalen COM-Port senden.\n';
}

if( DisableLPT == "1" ){
  SYS_2_2_3_A19 += 'Benutzer können keine Daten an den lokalen LPT-Port senden.\n';
}else{
  SYS_2_2_3_A19 += 'Benutzer können Daten an den lokalen LPT-Port senden.\n';
}

if( DisableDrive == "1" ){
  SYS_2_2_3_A19 += 'Laufwerke werden bei RDP-Sessions nicht eingebunden.\n';
  SYS_2_2_3_A19 += 'Dateiablagen werden bei RDP-Session nicht unterstützt.\n';
}else{
  SYS_2_2_3_A19 += 'Laufwerke werden bei RDP-Sessions eingebunden.\n';
  SYS_2_2_3_A19 += 'Dateiablagen werden bei RDP-Session unterstützt.\n';
}

if( DisableSmartCard == "0" ){
  SYS_2_2_3_A19 += 'Smartcard-Anschlüsse werden nicht eingebunden.\n';
}else{
  SYS_2_2_3_A19 += 'Smartcard-Anschlüsse werden eingebunden.\n';
}

if( DisablePlugAndPlay == "1" ){
  SYS_2_2_3_A19 += 'Unterstützte Plug-And-Play Geräte können in der RDP-Session nicht verwendet werden.\n\n';
}else{
  SYS_2_2_3_A19 += 'Unterstützte Plug-And-Play Geräte können in der RDP-Session verwendet werden.\n\n';
}


# SYS.2.2.3.A20 Einsatz der Benutzerkontensteuerung für privilegierte Konten
SYS_2_2_3_A20 = 'SYS.2.2.3.A20 Einsatz der Benutzerkontensteuerung für privilegierte Konten:\n';
if( get_kb_item("SMB/UAC") != 'success' ){
  SYS_2_2_3_A20 += 'Fehler: Die Registry konnte nicht ausgelesen werden.\n\n';
}else{
  EnableLUA = get_kb_item("SMB/UAC/EnableLUA");
  if( EnableLUA == '1' ){
    SYS_2_2_3_A20 += 'UAC ist auf dem Host aktiviert.\n';
  }else{
    SYS_2_2_3_A20 += 'UAC ist auf dem Host nicht aktiviert.\n';
  }

  ConsentPromptBehaviorUser = get_kb_item("SMB/UAC/ConsentPromptBehaviorUser");
  if( ConsentPromptBehaviorUser == '0' ){
    SYS_2_2_3_A20 += 'Anforderungen für erhöhte Rechte für Standardnutzer werden automatisch abgelehnt.\n';
  }else{
    SYS_2_2_3_A20 += 'Anforderungen für erhöhte Rechte für Standardnutzer werden nicht automatisch abgelehnt.\n';
  }

  ConsentPromptBehaviorAdmin = get_kb_item("SMB/UAC/ConsentPromptBehaviorAdmin");
  if( ConsentPromptBehaviorAdmin == '0' ){
    SYS_2_2_3_A20 += 'Administratoren erlangen erhöhte Rechte ohne Eingabeaufforderung.\n\n';
  }else if( ConsentPromptBehaviorAdmin == '1' ){
    SYS_2_2_3_A20 += 'Administratoren erlangen erhöhte Rechte nach Eingabeaufforderung zu Anmeldeinformationen auf einem sicheren Desktop.\n\n';
  }else if( ConsentPromptBehaviorAdmin == '2' ){
    SYS_2_2_3_A20 += 'Administratoren erlangen erhöhte Rechte nach Eingabeaufforderung zur Zustimmung auf einem sicheren Desktop.\n\n';
  }else if( ConsentPromptBehaviorAdmin == '3' ){                                                                                                                                                                                                                           
    SYS_2_2_3_A20 += 'Administratoren erlangen erhöhte Rechte nach Eingabeaufforderung zu Anmeldeinformationen.\n\n';
  }else if( ConsentPromptBehaviorAdmin == '4' ){
    SYS_2_2_3_A20 += 'Administratoren erlangen erhöhte Rechte nach Eingabeaufforderung zur Zustimmung.\n\n';
  }else if( ConsentPromptBehaviorAdmin == '5' ){
    SYS_2_2_3_A20 += 'Administratoren erlangen erhöhte Rechte nach Eingabeaufforderung zur Zustimmung für Nicht-Windows-Binärdateien.\n\n';
  }else{
    SYS_2_2_3_A20 += 'Die Einstellung für das Verhalten der Eingabeaufforderung für erhöhte Rechte für Administratoren konnte nicht bestimmt werden.\n\n';
  }
}


# SYS.2.2.3.A21 Einsatz des Encrypting File Systems EFS (CI)
SYS_2_2_3_A21 += 'SYS.2.2.3.A21 Einsatz des Encrypting File Systems EFS (CI):\n';
EFSAlgorithmID = get_kb_item("WMI/WMI_EFSAlgorithmID");
if( EFSAlgorithmID == "none" ){
  SYS_2_2_3_A21 += 'EFS wird nicht verwendet.\n';
}else if( EFSAlgorithmID == '6610' ){
  SYS_2_2_3_A21 += 'EFS wird mit einer AES 256-Bit Verschlüsselung verwendet.\n';
}else if( EFSAlgorithmID == '6603' ){
  SYS_2_2_3_A21 += 'EFS wird mit einer 3DES Verschlüsselung verwendet.\n';
}else{
  SYS_2_2_3_A21 += 'EFS wird verwendet. Die Art der Verschlüsselung konnte nicht ermittelt werden.\n';
}

if( LsaCfgFlags == "1" || LsaCfgFlags == "2" ){
  SYS_2_2_3_A21 += 'Credential Guard ist aktiviert. Die Verschlüsselung der lokalen Passwortspeicher mittels Syskey kann daher entfallen.\n\n';
}else{
  SYS_2_2_3_A21 += 'Credential Guard ist nicht aktiviert. Die Verschlüsselung der lokalen Passwortspeicher (z.B. mittels Syskey) muss manuell geprüft werden.\n\n';
}


# SYS.2.2.3.A22 Windows PowerShell (CIA)
SYS_2_2_3_A22 = 'SYS.2.2.3.A22 Windows PowerShell (CIA):\n';
WPS_Enabled = registry_get_dword(key:"Software\Policies\Microsoft\Windows\PowerShell", item:"EnableScripts");
ExecutionPolicy = registry_get_sz(key:"Software\Policies\Microsoft\Windows\PowerShell", item:"ExecutionPolicy");
EnableScriptBlockLogging = registry_get_dword(key:"Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", item:"EnableScriptBlockLogging");
EnableScriptBlockInvocationLogging = registry_get_dword(key:"Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", item:"EnableScriptBlockInvocationLogging");

if( WPS_Enabled == "1" ){
  SYS_2_2_3_A22 += 'Benutzer können die Windows PowerShell (WPS) als Option für ausführbare Programme auswählen.\n';
}else{
  SYS_2_2_3_A22 += 'Windows PowerShell (WPS) ist deaktiviert. Es können keine WPS-Dateien ausgeführt werden.\n';
}

if( ExecutionPolicy == "AllSigned"){
  SYS_2_2_3_A22 += 'Es dürfen nur signierte Scripts ausgeführt werden (ExecutionPolicy: AllSigned).\n';
}else{
  SYS_2_2_3_A22 += 'Die Option "ExecutionPolicy: AllSigned" ist nicht gesetzt. ';
  SYS_2_2_3_A22 += 'Dies sollte gesetzt werden, um sicherzustellen, dass nur signierte Scripte ausgeführt werden können.';
}

if( EnableScriptBlockLogging == "1" ){
  SYS_2_2_3_A22 += 'Die WPS-Ausführung wird protokolliert, unabhängig davon, ob diese interaktiv oder automatisch ausgeführt werden.\n';
}else{
  SYS_2_2_3_A22 += 'Die WPS-Ausführung wird nicht protokolliert. Dies sollte aktiviert werden.\n';
}

if( EnableScriptBlockInvocationLogging == "1" ){
  SYS_2_2_3_A22 += 'Der Aufruf der WPS wird geloggt. Dies kann zu einer hohen Anzahl an Log-Events führen.\n\n';
}else{
  SYS_2_2_3_A22 += 'Der Aufruf der WPS wird nicht geloggt.\n\n';
}


# SYS.2.2.3.A23 Erweiterter Schutz der Anmeldeinformationen in Windows 10 (CI)
SYS_2_2_3_A23 = 'SYS.2.2.3.A23 Erweiterter Schutz der Anmeldeinformationen in Windows 10 (CI):\n';
SecureBoot = registry_get_dword(key:"System\CurrentControlSet\Control\SecureBoot\State", item:"UEFISecureBootEnabled");
if( SecureBoot == "1" ){
  SYS_2_2_3_A23 += 'SecureBoot ist aktiviert.\n';
  LSASS = registry_get_dword(key:"SYSTEM\CurrentControlSet\Control\Lsa", item:"RunAsPPL");
  if( LSASS == "1" ){
    SYS_2_2_3_A23 += 'Der geschützte Modus für LSASS ist aktiviert. Der Status sollte bei Systemstart überwacht werden.\n';
  }else{
    SYS_2_2_3_A23 += 'Der geschützte Modus fpr LSASS ist nicht aktiviert. Dieser sollte aktiviert und der Status bei Systemstart überwacht werden.\n';
  } 
}else{
  BootOption = win_cmd_exec(cmd:'type C:\\Windows\\Panther\\setupact.log|find /i "Detected boot environment"', password:passwd, username:usrname_WmiCmd);
  if( BootOption ){
    UEFI = ereg(string:BootOption, pattern:"Detected boot environment: (EFI|UEFI)", icase:TRUE, multiline:TRUE);
  }
  
  SYS_2_2_3_A23 += 'SecureBoot ist deaktiviert.\n';
  if( UEFI ){
    SYS_2_2_3_A23 += 'Der Host ist ein UEFI-basiertes System. Dementsprechend sollte SecureBoot aktiviert werden.\n';
  }
}

RestrictedRemoteAdministration = registry_get_dword(key:"Software\Policies\Microsoft\Windows\CredentialsDelegation", item:"RestrictedRemoteAdministration");
RestrictedRemoteAdministrationType = registry_get_dword(key:"Software\Policies\Microsoft\Windows\CredentialsDelegation", item:"RestrictedRemoteAdministrationType");
if( RestrictedRemoteAdministration == "1" ){
  SYS_2_2_3_A23 += 'Die Option "Restricted Admin" ist mit folgender Einstellung aktiviert:\n';
  if( RestrictedRemoteAdministrationType == "1" ){
    SYS_2_2_3_A23 += '"Restricted Admin" muss verwendet werden, um eine RDP-Session herzustellen.\n';
  }else if( RestrictedRemoteAdministrationType == "2" ){
    SYS_2_2_3_A23 += '"Remote Credential Guard" muss verwendet werden, um eine RDP-Session herzustellen.\n';
  }else if( RestrictedRemoteAdministrationType == "3" ){
    SYS_2_2_3_A23 += '"Remote Credential Guard" oder "Restricted Admin" muss verwendet werden, um eine RDP-Session herzustellen.\n';
  }else{
    SYS_2_2_3_A23 += 'Es konnte keine Spezifikation gefunden werden.\n';
  }
  SYS_2_2_3_A23 += 'Es sollte "Restricted Admin" verwendet werden.\n';
}else{
  SYS_2_2_3_A23 += 'Die Option "Restricted Admin" ist nicht aktiviert. Ist eine Fernwartung per RDP vorgesehen, sollte diese aktiviert werden.\n';
}
SYS_2_2_3_A23 += '\n';

# SYS.2.2.3.A24 Aktivierung des Last-Access-Zeitstempels (A)
SYS_2_2_3_A24 = 'SYS.2.2.3.A24 Aktivierung des Last-Access-Zeitstempels (A):\n';
LastAccessTime = registry_get_dword(key:"SYSTEM\CurrentControlSet\Control\FileSystem", item:"NtfsDisableLastAccessUpdate");
if( LastAccessTime == "1" ){
  SYS_2_2_3_A24 += 'Der Last-Access-Zeitstempel ist deaktiviert.\n\n';
}else{
  SYS_2_2_3_A24 += 'Der Last-Access-Zeitstempel ist aktiviert.\n\n';
}


# SYS.2.2.3.A25Umgang mit Fernzugriffsfunktionen der "Connected User Experience and Telemetry" (CI)
SYS_2_2_3_A25 = 'SYS.2.2.3.A25 Umgang mit Fernzugriffsfunktionen der "Connected User Experience and Telemetry" (CI):\n';
Telemetry = registry_get_dword(key:"Software\Policies\Microsoft\Windows\DataCollection", item:"AllowTelemetry");
if( Telemetry == "0" ){
  SYS_2_2_3_A25 += 'Die Komponente "Telemetry" sendet minimale Daten an Microsoft. Die Einstellung entspricht der höchsten Sicherheitsstufe (GPO: Allow Telemetry, Wert: 0).\n';
}else{
  SYS_2_2_3_A25 += 'Die Komponente "Telemetry" sendet Daten an Microsoft. Dies sollte auf die sicherste Stufe (GPO: Allow Telemetry, Wert: 0) gesetzt werden.\n';
}

TelemetryProxyServer = registry_get_sz(key:"Software\Policies\Microsoft\Windows\DataCollection", item:"TelemetryProxyServer");
if( TelemetryProxyServer ){
  SYS_2_2_3_A25 += 'Mittel der GPO "Configure Connected User Experiences and Telemetry" kann ein Proxyserver bestimmt werden, an den Anfragen für \n';
  SYS_2_2_3_A25 += '"Connected User Experiences and Telemetry" gesendet werden sollen. Momentane Einstellung:\n' + TelemetryProxyServer + '\n';
}else{
  SYS_2_2_3_A25 += 'Mittel der GPO "Configure Connected User Experiences and Telemetry" kann ein Proxyserver bestimmt werden, an den Anfragen für \n';
  SYS_2_2_3_A25 += '"Connected User Experiences and Telemetry" gesendet werden sollen. Momentane ist dies nicht konfiguriert.\n';
}

DisableEnterpriseAuthProxy = registry_get_dword(key:"Software\Policies\Microsoft\Windows\DataCollection", item:"DisableEnterpriseAuthProxy");
if( DisableEnterpriseAuthProxy == "1" ){
  SYS_2_2_3_A25 += 'Die Komponente "Connected User Experiences and Telemetry" benutzt nicht automatisch einen authentifizierten Proxy um Daten an Microsoft zu senden.\n\n';
}else{
  SYS_2_2_3_A25 += 'Die Komponente "Connected User Experiences and Telemetry" benutzt automatisch einen authentifizierten Proxy um Daten an Microsoft zu senden.\n\n';
}


# Output
message += 'Basis-Absicherung:\n\n' + SYS_2_2_3_A1 + SYS_2_2_3_A2 + SYS_2_2_3_A3 + SYS_2_2_3_A4 + SYS_2_2_3_A5 + SYS_2_2_3_A6;
LEVEL = get_kb_item("GSHB/level");
if( LEVEL == 'Standard' || LEVEL == 'Kern'){
  message += '\n\nStandard-Absicherung:\n\n' + SYS_2_2_3_A7 + SYS_2_2_3_A8 + SYS_2_2_3_A9 + SYS_2_2_3_A10 + SYS_2_2_3_A11;
  message += SYS_2_2_3_A12 + SYS_2_2_3_A13 + SYS_2_2_3_A14 + SYS_2_2_3_A15 + SYS_2_2_3_A16 + SYS_2_2_3_A17;
  message += SYS_2_2_3_A18 + SYS_2_2_3_A19 + SYS_2_2_3_A20;
}
if( LEVEL == 'Kern' ){
  message += '\n\nKern-Absicherung:\n\n' + SYS_2_2_3_A21 + SYS_2_2_3_A22 + SYS_2_2_3_A23 + SYS_2_2_3_A24 + SYS_2_2_3_A25;
}

log_message(port:0, data:message);
wmi_close(wmi_handle:handle);
exit(0);
