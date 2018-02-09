##############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_SYS.2.2.2.nasl 8725 2018-02-08 15:16:38Z cfischer $
#
# IT-Grundschutz Baustein: SYS.2.2.2 Clients unter Windows 8.1
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
  script_oid("1.3.6.1.4.1.25623.1.0.109037");
  script_version("$Revision: 8725 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-08 16:16:38 +0100 (Thu, 08 Feb 2018) $");
  script_tag(name:"creation_date", value:"2017-11-24 07:42:28 +0200 (Fri, 24 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");  
  script_name('SYS.2.2.2 Clients unter Windows 8.1');
  script_xref(name : "URL" , value : " https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/bausteine/SYS/SYS_2_2_2_Clients_unter_Windows_8_1.html ");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB-ITG");
  script_dependencies("GSHB/GSHB_WMI_OSInfo.nasl", "logins.nasl", "netbios_name_get.nasl", "GSHB/GSHB_WMI_Antivir.nasl", "GSHB/GSHB_SMB_UAC_Config.nasl", "GSHB/GSHB_WMI_EFS.nasl");
  script_tag(name : "summary" , value : 'Zielsetzung dieses Bausteins ist der Schutz von Informationen, 
      die durch und auf Windows 8.1-Clients verarbeiten werden.');
  
  exit(0);
}

include("host_details.inc");
include("wmi_user.inc");
include("smb_nt.inc");
include("misc_func.inc");
include("wmi_rsop.inc");

Windows_Version = get_kb_item("WMI/WMI_OSVER");
Windows_Name = get_kb_item("WMI/WMI_OSNAME");

if( Windows_Version != "6.3" ||  "windows 8.1" >!< tolower(Windows_Name) ){
  set_kb_item(name:"GSHB/SYS.2.2.2", value:"error");
  log_message(data:"Auf dem Host scheint kein Microsoft Windows 8.1 Betriebsystem installiert zu sein,
      oder es konnte keine Verbindung zum Host hergestellt werden.");
  exit(0);
}

host    = get_host_ip();
usrname = kb_smb_login(); 
domain  = kb_smb_domain();
if( domain ){
  usrname = domain + '\\' + usrname;
}
passwd  = kb_smb_password();



# SYS.2.2.2.A1 Geeignete Auswahl einer Windows 8.1-Version
SYS_2_2_2_A1 = 'SYS.2.2.2.A1 Geeignete Auswahl einer Windows 8.1-Version:\n';
Win_OSArchitecture = get_kb_item("WMI/WMI_OSArchitecture");
if( tolower(Win_OSArchitecture) =~ "64.*bit" ){
  SYS_2_2_2_A1 += 'Auf dem Host wird eine 64-Bit Version von Windows 8.1 eingesetzt.\n\n';
}else{
  SYS_2_2_2_A1 += 'Auf dem Host wird keine 64-Bit Version von Windows 8.1 eingesetzt.\n';
  SYS_2_2_2_A1 += 'Aufgrund der erweiterten Sicherheitsfeatures einer 64-Bit Version sollte diese eingesetzt werden.\n\n';
}

# SYS.2.2.2.A2 Festlegung eines Anmeldeverfahrens
SYS_2_2_2_A2 = 'SYS.2.2.2.A2 Festlegung eines Anmeldeverfahrens:\n';
reg_key = "SOFTWARE\Policies\Microsoft\Windows\System";
AllowPinLogon = registry_get_dword(key:reg_key, item:"AllowDomainPINLogon", type:"HKLM");
if( AllowPinLogon == 0 ){
  SYS_2_2_2_A2 += 'Ein Login mit PIN ist auf dem Host nicht erlaubt.\n';
}else if( AllowPinLogon == 1 ){
  SYS_2_2_2_A2 += 'Ein Login mit PIN ist auf dem Host erlaubt.\n';
}else{
  SYS_2_2_2_A2 += 'Ein Login mit PIN wurde auf dem Host nicht konfiguriert.\n';
  SYS_2_2_2_A2 += 'Ein User kann ein Login mit PIN aktivieren.\n';
  SYS_2_2_2_A2 += 'Ein Login mit PIN sollte erlaubt oder nicht erlaubt sein.\n';
}

AllowPictureLogon = registry_get_dword(key:reg_key, item:"BlockDomainPicturePassword", type:"HKLM");
if( AllowPictureLogon == 1 ){
  SYS_2_2_2_A2 += 'Ein Login mit Fotogeste ist auf dem Host nicht erlaubt.\n\n';
}else if( AllowPictureLogon == 0 ){
  SYS_2_2_2_A2 += 'Ein Login mit Fotogeste ist auf dem Host erlaubt.\n\n';
}else{
  SYS_2_2_2_A2 += 'Ein Login mit Fotogeste wurde auf dem Host nicht konfiguriert.\n';
  SYS_2_2_2_A2 += 'Ein User kann ein Login mit Fotogeste aktivieren.\n';
  SYS_2_2_2_A2 += 'Ein Login mit Fotogeste sollte erlaubt oder nicht erlaubt sein.\n\n';
}


# SYS.2.2.2.A3 Einsatz von Viren-Schutzprogrammen
SYS_2_2_2_A3 = 'SYS.2.2.2.A3 Einsatz von Viren-Schutzprogrammen:\n';
SecurityCenter2 = get_kb_item("WMI/Antivir/SecurityCenter2");
SecurityCenter2 = split(SecurityCenter2, keep:FALSE);
if( max_index(SecurityCenter2) <= 1 ){
  SYS_2_2_2_A3 += 'Es konnte kein Viren-Schutzprogramm im Security Center gefunden werden.\n';
  SYS_2_2_2_A3 += 'Stellen Sie sicher, dass gleich- oder höherwertige Maßnahmen zum Schutz des IT-Sytems vor einer Infektion mit Schadsoftware getroffen wurde.\n\n';
}else{
  SYS_2_2_2_A3 += 'Folgende Schutzprogramme sind installiert:\n';

  # get state of each AntiVir program (can be more than one)
  foreach line (SecurityCenter2){
    line = split(line, sep:'|', keep:FALSE);
    
    # skip header
    if( tolower(line[0]) == 'displayname' ){
      continue;
    }

    SYS_2_2_2_A3 += line[0] + '\n';
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

    SYS_2_2_2_A3 += 'Status: ' + ProtectionStatus_Res + '\n';
    SYS_2_2_2_A3 += 'Zeitstempel: ' + UpToDate_Res + '\n\n';
  }
}


# SYS.2.2.2.A4 Beschaffung von Windows 8.1
SYS_2_2_2_A4 = 'SYS.2.2.2.A4 Beschaffung von Windows 8.1:\n';
SYS_2_2_2_A4 += 'Diese Vorgabe kann nicht implementiert werden.\n\n';

# SYS.2.2.2.A5 Lokale Sicherheitsrichtlinien
SYS_2_2_2_A5 = 'SYS.2.2.2.A5 Lokale Sicherheitsrichtlinien:\n';

handle = wmi_connect(host:host, username:usrname, password:passwd, ns:'root\\rsop\\computer');
if( !handle ){
  set_kb_item(name:"ITG/SYS.2.2.2", value:"error");
  SYS_2_2_2_A5 += "Es war nicht möglich, ein Verbindung mit dem Host aufzubauen.";
}else{
  AuditPolicy = wmi_rsop_auditpolicy(handle:handle, select:"Category");
  if( AuditPolicy ){    
    AuditPolicy = split(AuditPolicy, keep:FALSE);
    SYS_2_2_2_A5 += 'Folgende Überwachungsrichtlinien sind auf dem Host aktiviert:\n';
    foreach line (AuditPolicy){
      line = split(line, sep:'|', keep:FALSE);
   
      if( tolower(line[0]) == 'category' ){
        continue;
      }

      SYS_2_2_2_A5 += line[0] + '\n';
    }
    SYS_2_2_2_A5 += '\n';
  }else{
    SYS_2_2_2_A5 +='Die Überwachungsrichtlinien konnten nicht ausgelesen werden.\n\n';
  }

  UserPrivilegeRight = wmi_rsop_userprivilegeright(handle:handle, select:"AccountList,UserRight");
  if( UserPrivilegeRight ){
    UserPrivilegeRight = split(UserPrivilegeRight, keep:FALSE);
    SYS_2_2_2_A5 += 'Folgende Benutzerrechte sind zugewiesen:\n';
    foreach line (UserPrivilegeRight){
      line = split(line, sep:'|', keep:FALSE);
      
      if( tolower(line[0]) == 'accountlist' ){
        continue;
      }

      SYS_2_2_2_A5 += line[max_index(line)-1] + ' : ';
      
      for( y = 0; y <= max_index(line)-3; y++ ){
        SYS_2_2_2_A5 += line[y];
        if( y == max_index(line)-3 ){
          SYS_2_2_2_A5 += '\n';
        }else{
          SYS_2_2_2_A5 += ', ';
        }
      }
    }
    
    SYS_2_2_2_A5 += '\n';
  }else{
    SYS_2_2_2_A5 += 'Die zugewiesenen Benutzerrechte konnten nicht ausgelesen werden.\n';
  }
}
SYS_2_2_2_A5 += 'Es werden lediglich die Überwachungsrichtlinien und die Zuweisung von Benutzerrechten abgefragt.\n\n';


# SYS.2.2.2.A6 Datei- und Freigabeberechtigungen
SYS_2_2_2_A6 = 'SYS.2.2.2.A6 Datei- und Freigabeberechtigungen:\n';
SYS_2_2_2_A6 += 'Diese Vorgabe kann nicht implementiert werden.\n\n';

# SYS.2.2.2.A7 Einsatz der Windows-Benutzerkontensteuerung UAC
SYS_2_2_2_A7 = 'SYS.2.2.2.A7 Einsatz der Windows-Benutzerkontensteuerung UAC:\n';
if( get_kb_item("SMB/UAC") != 'success' ){
  SYS_2_2_2_A7 += 'Fehler: Die Registry konnte nicht ausgelesen werden.\n\n';
}else{
  EnableLUA = get_kb_item("SMB/UAC/EnableLUA");
  if( EnableLUA == '1' ){
    SYS_2_2_2_A7 += 'UAC ist auf dem Host aktiviert.\n';
  }else{
    SYS_2_2_2_A7 += 'UAC ist auf dem Host nicht aktiviert.\n';
  }

  ConsentPromptBehaviorUser = get_kb_item("SMB/UAC/ConsentPromptBehaviorUser");
  if( ConsentPromptBehaviorUser == '0' ){
    SYS_2_2_2_A7 += 'Anforderungen für erhöhte Rechte für Standardnutzer werden automatisch abgelehnt.\n';
  }else{
    SYS_2_2_2_A7 += 'Anforderungen für erhöhte Rechte für Standardnutzer werden nicht automatisch abgelehnt.\n';
  }

  ConsentPromptBehaviorAdmin = get_kb_item("SMB/UAC/ConsentPromptBehaviorAdmin");
  if( ConsentPromptBehaviorAdmin == '0' ){
    SYS_2_2_2_A7 += 'Administratoren erlangen erhöhte Rechte ohne Eingabeaufforderung.\n\n';
  }else if( ConsentPromptBehaviorAdmin == '1' ){
    SYS_2_2_2_A7 += 'Administratoren erlangen erhöhte Rechte nach Eingabeaufforderung zu Anmeldeinformationen auf einem sicheren Desktop.\n\n';
  }else if( ConsentPromptBehaviorAdmin == '2' ){
    SYS_2_2_2_A7 += 'Administratoren erlangen erhöhte Rechte nach Eingabeaufforderung zur Zustimmung auf einem sicheren Desktop.\n\n';
  }else if( ConsentPromptBehaviorAdmin == '3' ){
    SYS_2_2_2_A7 += 'Administratoren erlangen erhöhte Rechte nach Eingabeaufforderung zu Anmeldeinformationen.\n\n';
  }else if( ConsentPromptBehaviorAdmin == '4' ){
    SYS_2_2_2_A7 += 'Administratoren erlangen erhöhte Rechte nach Eingabeaufforderung zur Zustimmung.\n\n';
  }else if( ConsentPromptBehaviorAdmin == '5' ){
    SYS_2_2_2_A7 += 'Administratoren erlangen erhöhte Rechte nach Eingabeaufforderung zur Zustimmung für Nicht-Windows-Binärdateien.\n\n';
  }else{
    SYS_2_2_2_A7 += 'Die Einstellung für das Verhalten der Eingabeaufforderung für erhöhte Rechte für Administratoren konnte nicht bestimmt werden.\n\n';
  }
}

# SYS.2.2.2.A8 Verwendung der Heimnetzgruppen-Funktion [Benutzer]
SYS_2_2_2_A8 = 'SYS.2.2.2.A8 Verwendung der Heimnetzgruppen-Funktion:\n';
FileAndPrint = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\FileAndPrint", item:"Enabled");
RemoteAddresses = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\FileAndPrint", item:"RemoteAddresses");
if( FileAndPrint == '0' ){
  SYS_2_2_2_A8 += 'Die UDP-Ports 139, 138 und TCP-Pots 139, 445 werden blockiert. Datei- und Druckerfreigabe ist verhindert.\n';
  if( RemoteAddresses ){
    SYS_2_2_2_A8 += 'Für IP-Adressen gelten Ausnahme-Regelungen:\n' + RemoteAddresses + '\n\n';
  }
}else{
  SYS_2_2_2_A8 += 'Die UDP-Ports 139, 138 und TCP-Pots 139, 445 werden nicht blockiert. Datei- und Druckerfreigabe ist nicht verhindert.\n';
}

HomeGroup = registry_get_dword(key:"Software\Policies\Microsoft\Windows\HomeGroup", item:"DisableHomeGroup");
if( HomeGroup == "1" ){
  SYS_2_2_2_A8 += 'Benutzer können den Host nicht zu einer Heimnetzgruppe hinzufügen.\n\n';
}else{
  SYS_2_2_2_A8 += 'Benutzer können den Host zu einer Heimnetzgruppe hinzufügen. Diese Einstellung sollte begründet sein.\n\n';
}


# SYS.2.2.2.A9 Datenschutz und Datensparsamkeit bei Windows 8.1-Clients
SYS_2_2_2_A9 = 'SYS.2.2.2.A9 Datenschutz und Datensparsamkeit bei Windows 8.1-Clients:\n';
SYS_2_2_2_A9 += 'Diese Vorgabe kann nicht implementiert werden.\n\n';


# SYS.2.2.2.A10 Integration von Online-Konten in das Betriebssystem
SYS_2_2_2_A10 = 'SYS.2.2.2.A10 Integration von Online-Konten in das Betriebssystem:\n';
query = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeDenyInteractiveLogonRight' AND precedence=1";
SeDenyInteractiveLogonRight = wmi_query(wmi_handle:handle, query:query);
if( ! SeDenyInteractiveLogonRight ){
  SYS_2_2_2_A10 += 'Es konnten keine Benutzer gefunden werden, denen die lokale Anmeldung verweigert wird (GPO "Lokale Anmeldung Verweigern").\n';
}else{
  SeDenyInteractiveLogonRight = split(SeDenyInteractiveLogonRight, keep:FALSE);
  SYS_2_2_2_A10 += 'Folgenden Benutzern wird die lokale Anmeldung verweigert (GPO "Lokale Anmeldung Verweigern"):\n';
  foreach line (SeDenyInteractiveLogonRight){
    line = split(line, sep:'|', keep:FALSE);
    if( tolower(line[0]) == 'accountlist' ){
      continue;
    }

    for( y=0; y<=max_index(line)-3; y++ ){
      SYS_2_2_2_A10 += line[y];
      if( y == max_index(line)-3 ){
        SYS_2_2_2_A10 += '\n';
      }else{
        SYS_2_2_2_A10 += ', ';
      }
    }
  }
}

query = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeInteractiveLogonRight' AND precedence=1";
SeInteractiveLogonRight = wmi_query(wmi_handle:handle, query:query);
if( ! SeInteractiveLogonRight ){
  SYS_2_2_2_A10 += 'Es konnten keine Benutzer gefunden werden, denen die lokale Anmeldung zugelassen wird (GPO "Lokale Anmeldung Zulassen").\n\n';
}else{
  SeInteractiveLogonRight = split(SeInteractiveLogonRight, keep:FALSE);
  SYS_2_2_2_A10 += 'Folgenden Benutzern wird die lokale Anmeldung zugelassen (GPO "Lokale Anmeldung Zulassen"):\n';
  foreach line (SeInteractiveLogonRight){
    line = split(line, sep:'|', keep:FALSE);
    if( tolower(line[0]) == 'accountlist' ){
      continue;
    }

    for( y=0; y<=max_index(line)-3; y++ ){
      SYS_2_2_2_A10 += line[y];
      if( y == max_index(line)-3 ){
        SYS_2_2_2_A10 += '\n\n';
      }else{
        SYS_2_2_2_A10 += ', ';
      }
    }
  }
}

# SYS.2.2.2.A11 Konfiguration von Synchronisationsmechanismen in Windows 8.1
SYS_2_2_2_A11 = 'SYS.2.2.2.A11 Konfiguration von Synchronisationsmechanismen in Windows 8.1:\n';
DisableSettingSync = registry_get_dword(key:"Software\Policies\Microsoft\Windows\SettingSync", item:"DisableSettingSync");
if( DisableSettingSync == '2' ){
  SYS_2_2_2_A11 += 'Einstellungen werden nicht synchronisiert.\n';
}else{
  SYS_2_2_2_A11 += 'Synchronisation der Einstellungen werden nicht unterbunden. ';
  SYS_2_2_2_A11 += 'Dies sollte verhindert werden (GPO: "Synchronisation verhindern")\n';
}

ConnectedSearchUseWeb = registry_get_dword(key:"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ConnectedSearch", item:"ConnectedSearchUseWeb");
if( ConnectedSearchUseWeb == '0' ){
  SYS_2_2_2_A11 += 'Bei einer Suche mit Bing werden keine Internetsuchvorschläge einbezogen.\n';
}else{
  SYS_2_2_2_A11 += 'Bei einer Suche mit Bing werden Internetsuchvorschläge einbezogen. ';
  SYS_2_2_2_A11 += 'Dies sollte verhindert werden (GPO: "Nicht im Web suchen und keine Webergebnisse anzeigen").\n';
}

ConnectedSearchPrivacy = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows\Windows Search", item:"ConnectedSearchPrivacy");
if( ConnectedSearchPrivacy == '2' ){
  SYS_2_2_2_A11 += 'Bei einer Suche mit Bing werden lediglich Anwendungsinformationen anonymisiert übertragen.\n';
}else{
  SYS_2_2_2_A11 += 'Bei einer Suche mit Bing werden Nutzerdaten übertragen. ';
  SYS_2_2_2_A11 += 'Dies sollte verhindert werden (GPO: "Festlegen der in der Suche freizugebenden Informationen")\n';
}

DisableFileSync = registry_get_dword(key:"Software\Policies\Microsoft\Windows\Skydrive", item:"DisableFileSync");
if( DisableFileSync == '1' ){
  SYS_2_2_2_A11 += 'OneDrive ist als Speicherort für Dateien deaktiviert.\n';
}else{
  SYS_2_2_2_A11 += 'OneDrive wird als Speicherort für Dateien nicht verhindert. ';
  SYS_2_2_2_A11 += 'Dies sollte verhindert werden (GPO: "verwendung von OneDrive für die Datenspeicherung verhindern")\n';
}

DisableLibrariesDefaultSaveToSkyDrive = registry_get_dword(key:"Software\Policies\Microsoft\Windows\Skydrive", item:"DisableLibrariesDefaultSaveToSkyDrive");
if( DisableLibrariesDefaultSaveToSkyDrive == '1' ){
  SYS_2_2_2_A11 += 'Dateien und Dokumente werden standardmäßig nicht auf OneDrive gespeichert.\n\n';
}else{
  SYS_2_2_2_A11 += 'Dateien und Dokumente werden standardmäßig auf OneDrive gespeichert. ';
  SYS_2_2_2_A11 += 'Dies sollte verhindert werden (GPO: "Dokumente standardmäßig auf OneDrive speichern")\n\n';
}


# SYS.2.2.2.A12 Zentrale Authentifizierung in Windows-Netzwerken
SYS_2_2_2_A12 = 'SYS.2.2.2.A12 Zentrale Authentifizierung in Windows-Netzwerken:\n';
SYS_2_2_2_A12 += 'Diese Vorgabe kann nicht implementiert werden.\n\n';

# SYS.2.2.2.A13 Anbindung von Windows 8.1 an AppStores
SYS_2_2_2_A13 = 'SYS.2.2.2.A13 Anbindung von Windows 8.1 an AppStores:\n';
RemoveWindowsStore = registry_get_dword(key:"Software\Policies\Microsoft\WindowsStore", item:"RemoveWindowsStore");
if( RemoveWindowsStore == '1' ){
  SYS_2_2_2_A13 += 'Windows Store ist deaktiviert.\n';
}else{
  SYS_2_2_2_A13 += 'Windows Store ist nicht deaktiviert. Dieser sollte deaktiviert werden (GPO: "Windows Store deaktivieren")\n';
}

AutoDownload = registry_get_dword(key:"Software\Policies\Microsoft\WindowsStore", item:"AutoDownload");
if( AutoDownload == '2' ){
  SYS_2_2_2_A13 += 'Automatischer Download und Installation von Updates aus dem Windows Store ist deaktiviert.\n\n';
}else{
  SYS_2_2_2_A13 += 'Automatischer Download und Installation von Updates aus dem Windows Store ist nicht deaktiviert.\n';
  SYS_2_2_2_A13 += 'Dies sollten verhindert werden (GPO: "Automatischer Download und Installation von Updates abstellen")\n\n';
}


# SYS.2.2.2.A14 Anwendungssteuerung mit Software Restriction Policies und AppLocker
SYS_2_2_2_A14 = 'SYS.2.2.2.A14 Anwendungssteuerung mit Software Restriction Policies und AppLocker (CIA):\n';
key = "SOFTWARE\Policies\Microsoft\Windows\Safer";
if( registry_key_exists(key:key) ){
  SYS_2_2_2_A14 += 'Software Restriction Policies (SRP) sind auf dem Host vorhanden. ';
  SYS_2_2_2_A14 += 'Bitte prüfen Sie die Konfiguration der SRP.\n';
}else{
  SYS_2_2_2_A14 += 'Software Restriction Policies (SRP) sind nicht auf dem Host vorhanden.\n';
}

key = "Software\Policies\Microsoft\Windows\SrpV2";
if( registry_key_exists(key:key) ){
  SYS_2_2_2_A14 += 'AppLocker ist auf dem Host vorhanden.\n';
  SYS_2_2_2_A14 += 'Bitte prüfen Sie die Konfiguration von AppLocker.\n\n';
}else{
  SYS_2_2_2_A14 += 'AppLocker ist nicht auf dem Host vorhanden.\n\n';
} 


# SYS.2.2.2.A15 Verschlüsselung des Dateisystems mit EFS
SYS_2_2_2_A15 = 'SYS.2.2.2.A15 Verschlüsselung des Dateisystems mit EFS (CI):\n';
EncrFile = get_kb_item("WMI/WMI_EncrFile");
EncrDir = get_kb_item("WMI/WMI_EncrDir");
EFSAlgorithmID = get_kb_item("WMI/WMI_EFSAlgorithmID");

if( EFSAlgorithmID == "none" ){
  SYS_2_2_2_A15 += 'EFS wird nicht verwendet.\n';
}else if( EFSAlgorithmID == '6610' ){
  SYS_2_2_2_A15 += 'EFS wird mit einer AES 256-Bit Verschlüsselung verwendet.\n';
}else if( EFSAlgorithmID == '6603' ){
  SYS_2_2_2_A15 += 'EFS wird mit einer 3DES Verschlüsselung verwendet.\n';
}else{
  SYS_2_2_2_A15 += 'EFS wird verwendet. Die Art der Verschlüsselung konnte nicht ermittelt werden.\n';
}

if( EncrFile == "none" ){
  SYS_2_2_2_A15 += 'Es wurden keine verschlüsselten Dateien gefunden.\n';
}else{
  SYS_2_2_2_A15 += 'Folgende Dateien liegen verschlüsselt vor:\n' + EncrFile + '\n\n';
}

if( EncrDir == "none" ){
  SYS_2_2_2_A15 += 'Es wurden keine verschlüsselten Odner gefunden.\n';
}else{
  SYS_2_2_2_A15 += 'Folgende Ordner liegen verschlüsselt vor:\n' + EncrFile + '\n\n';
}


# SYS.2.2.2.A16 Verwendung der Windows PowerShell
SYS_2_2_2_A16 = 'SYS.2.2.2.A16 Verwendung der Windows PowerShell (CIA):\n';
SYS_2_2_2_A16 += 'Die Ausführung von Windows PowerShell (WPS) Dateien sollte z.B. durch AppLocker und / oder SRP verhindert werden.\n';
SYS_2_2_2_A16 += 'Bitte konfigurieren Sie AppLocker und / oder SRP dementsprechend.\n\n';


# SYS.2.2.2.A17 Sicherer Einsatz des Wartungscenters (CIA)
SYS_2_2_2_A17 += 'SYS.2.2.2.A17 Sicherer Einsatz des Wartungscenters (CIA):\n';
query = "select StartMode from Win32_Service WHERE Name='DPS' OR Name='WDiSvcHost' OR Name='WerSvc'";
StartModes = wmi_query(wmi_handle:handle, query:query);
StartModes = ereg_replace(string:StartModes, pattern:"\|", replace:' : ');
SYS_2_2_2_A17 += StartModes;
SYS_2_2_2_A17 += '\nBitte überprüfen Sie die Einstellungen des Wartungscenters und deaktivieren Sie gegebenenfalls Einstellungen.\n\n';


# SYS.2.2.2.A18 Aktivierung des Last-Access-Zeitstempels (A)
SYS_2_2_2_A18 = 'SYS.2.2.2.A18 Aktivierung des Last-Access-Zeitstempels (A):\n';
LastAccessTime = registry_get_dword(key:"SYSTEM\CurrentControlSet\Control\FileSystem", item:"NtfsDisableLastAccessUpdate");
if( LastAccessTime == "1" ){
  SYS_2_2_2_A18 += 'Der Last-Access-Zeitstempel ist deaktiviert.\n\n';
}else{
  SYS_2_2_2_A18 += 'Der Last-Access-Zeitstempel ist aktiviert.\n\n';
}


# SYS.2.2.2.A19 Verwendung der Anmeldeinformationsverwaltung (C)
SYS_2_2_2_A19 = 'SYS.2.2.2.A19 Verwendung der Anmeldeinformationsverwaltung (C):\n';
DisableTresor = registry_get_dword(key:"System\CurrentControlSet\Control\Lsa", item:"DisableDomainCreds");
if( DisableTresor == "1" ){
  SYS_2_2_2_A19 += 'Zugangsdaten können nicht gespeichert werden (der sogenannte "Tresor" ist deaktiviert).\n\n';
}else{
  SYS_2_2_2_A19 += 'Zugangsdaten können gespeichert werden (der sogenannte "Tresor" ist aktiviert).\n\n';
}

# SYS.2.2.2.A20 Sicherheit beim Fernzugriff über RDP (CIA)
SYS_2_2_2_A20 = 'SYS.2.2.2.A20 Sicherheit beim Fernzugriff über RDP (CIA):\n';
RDPEnabled = registry_get_dword(key:"SYSTEM\CurrentControlSet\Control\Terminal Server", item:"fDenyTSConnection");
if( RDPEnabled == "1" ){;
  SYS_2_2_2_A20 += 'RDP ist auf dem Host aktiviert.\n';
}else{
  SYS_2_2_2_A20 += 'RDP ist auf dem Host deaktiviert.\n';
}

AlwaysPromptPassword = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", item:"fPromptForPassword");
if( AlwaysPromptPassword == "1" ){
  SYS_2_2_2_A20 += 'Bei der Verbindungsherstellung wird immer eine Kennworteingabe verlangt.\n';
}else{
  SYS_2_2_2_A20 += 'Bei der Verbindungsherstellung wird nicht immer eine Kennworteingabe verlangt. Die Kennworteingabe sollte aktiviert werden.\n';
}

NetworkLevelAuthentication = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", item:"UserAuthentication");
if( NetworkLevelAuthentication == "1" ){
  SYS_2_2_2_A20 += 'Benutzerauthentifizierung mit Authentifzierung auf Netzwerkebene ist für Remoteverbindungen erforderlich.\n';
}else{
  SYS_2_2_2_A20 += 'Benutzerauthentifizierung mit Authentifzierung auf Netzwerkebene ist für';
  SYS_2_2_2_A20 += 'Remoteverbindungen nicht erforderlich. Dies sollte aktiviert werden.\n';
}

EncryptionLevel = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", item:"MinEncryptionLevel");
if( EncryptionLevel == "3" ){
  SYS_2_2_2_A20 += 'Die höchste Verschlüsselungsstufe wird verwendet (128 Bit).\n';
}else{
  SYS_2_2_2_A20 += 'Die höchste Verschlüsselungsstufe wird nicht verwendet. Diese sollte verwendet werden (128 Bit Verschlüsselung).\n';
}

OfferRemoteAssistance = registry_get_dword(key:"Software\policies\Microsoft\Windows NT\Terminal Services", item:"fAllowUnsolicited");
if( OfferRemoteAssistance == "0" ){
  SYS_2_2_2_A20 += 'Remoteunterstützung anbieten ist deaktiviert.\n';
}else{
  SYS_2_2_2_A20 += 'Remoteunterstützung anbieten ist nicht deaktiviert. Dies sollte deaktiviert sein.\n';
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
  SYS_2_2_2_A20 += 'Die maximale Gültigkeitsdauer der Einladung beträgt ' + MaxTicketExpiry + MaxTicketExpiryUnits;
}else{
  SYS_2_2_2_A20 += 'Es ist keine maximale Gültigkeitsdauer der Einladung konfiguriert. Diese sollte eine angemessene Größe haben.\n';
}

DisablePasswordSaving = registry_get_dword(key:"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", item:"DisablePasswordSaving");
if( DisablePasswordSaving == "1" ){
  SYS_2_2_2_A20 += 'Benutzer dürfen keine Kennwörter speichern (automatische Kennwortanmeldung ist deaktiviert).\n';
}else{
  SYS_2_2_2_A20 += 'Benutzer dürfen Kennwörter speichern. Die automatische Kennwortanmeldung sollte deaktiviert werden.\n';
}

SYS_2_2_2_A20 += 'Bitte prüfen Sie die Benutzerrechte der Gruppe der berechtigten Benutzer für dein Remote-Desktopzugriff manuell.\n';
SYS_2_2_2_A20 += 'Eine Remote-Unterstützung sollte nur nach einer Einladung über EasyConnect oder auf Grundlage einer Einladungsdatei erfolgen.\n\n';


# SYS.2.2.2.A21 Einsatz von File und Registry Virtualization (CI)
SYS_2_2_2_A21 = 'SYS.2.2.2.A21 Einsatz von File und Registry Virtualization (CI):\n';
Virtualization = get_kb_item("SMB/UAC/EnableVirtualization");

if( Virtualization == "1" ){
  SYS_2_2_2_A21 += 'File und Registry Virtualization sind aktiviert.\n';
}else{
  SYS_2_2_2_A21 += 'File und Registry Virtualization sind deaktiviert.\n';
}


# Output
message += 'Basis-Absicherung:\n\n' + SYS_2_2_2_A1 + SYS_2_2_2_A2 + SYS_2_2_2_A3;
LEVEL = get_kb_item("GSHB/level");
if( LEVEL == 'Standard' || LEVEL == 'Kern'){
  message += '\n\nStandard-Absicherung:\n\n' + SYS_2_2_2_A4 + SYS_2_2_2_A5 + SYS_2_2_2_A6 + SYS_2_2_2_A7;
  message += SYS_2_2_2_A8 + SYS_2_2_2_A9 + SYS_2_2_2_A10 + SYS_2_2_2_A11 + SYS_2_2_2_A12 + SYS_2_2_2_A13;
}
if( LEVEL == 'Kern' ){
  message += '\n\nKern-Absicherung:\n\n' + SYS_2_2_2_A14 + SYS_2_2_2_A15 + SYS_2_2_2_A16 + SYS_2_2_2_A17;
  message += SYS_2_2_2_A18 + SYS_2_2_2_A19 + SYS_2_2_2_A20 + SYS_2_2_2_A21;
}

log_message(port:0, data:message);
wmi_close(wmi_handle:handle);
exit(0);
