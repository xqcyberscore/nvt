##############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_SYS.1.3.nasl 8271 2018-01-02 15:08:13Z emoss $
#
# IT-Grundschutz Baustein: SYS.1.3 Server unter Unix
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
  script_oid("1.3.6.1.4.1.25623.1.0.109036");
  script_version("$Revision: 8271 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-02 16:08:13 +0100 (Tue, 02 Jan 2018) $");
  script_tag(name:"creation_date", value:"2017-11-15 14:42:28 +0200 (Wed, 15 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");  
  script_name('SYS.1.3 Server unter Unix');

  script_xref(name : "URL" , value : " https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/bausteine/SYS/SYS_1_3_Server_unter_Unix.html ");
  
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_dependencies("gather-package-list.nasl", "GSHB/GSHB_SSH_AppArmor_SeLinux.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", "Compliance/Launch/GSHB-ITG");
  script_tag(name : "summary" , value : 'Zielsetzung des Bausteins ist der Schutz von Informationen, die von Unix-Servern verarbeitet werden.');
  
  exit(0);
}

include("ssh_func.inc");
include("misc_func.inc");

port = kb_ssh_transport();
host_ip = get_host_ip();

sock = ssh_login_or_reuse_connection();
if( !sock ) {
  error = get_ssh_error();
  if( !error )
    error = "No SSH Port or Connection!";
    log_message(port:port, data:error);
    exit(0); 
}

is_debian = get_kb_item("ssh/login/debian_linux");
if( is_debian != '1' ){
  log_message(port:0, data:'Der Host ist kein Debian System. Momentan werden lediglich Debian Server unterstützt.\n');
  exit(0);
}

debian_version = get_kb_item("ssh/login/release");

# SYS.1.3.A1 Benutzerauthentisierung unter Unix
SYS_1_3_A1 = 'SYS.1.3.A1 Benutzerauthentisierung unter Unix:\n';
SYS_1_3_A1 += 'Diese Vorgabe kann nicht implementiert werden.\n\n';

# SYS.1.3.A2 Sorgfältige Vergabe von IDs
SYS_1_3_A2 = 'SYS.1.3.A2 Sorgfältige Vergabe von IDs:\n';
cmd = 'getent passwd | cut -f1 -d: | uniq -c -d';
Logins = ssh_cmd(socket:sock, cmd:cmd);
if( "command not found" >< tolower(Logins) ){
  SYS_1_3_A2 += 'Der Befehl "getent", "uniq" oder "cut" ist dem System nicht bekannt. Diese Vorgabe kann nicht überprüft werden.\n';
}else if( "permission denied" >< tolower(Logins) ){
  SYS_1_3_A2 += 'Die Datei /etc/passwd konnte nicht gelesen werden (Keine Berechtigung).\n';
}else{
  if( Logins ){
    SYS_1_3_A2 += 'Folgende Login-Namen sind mehrfach in der Datei /etc/passwd enthalten:\n' + Logins + '\n\n';
  }else{
    SYS_1_3_A2 += 'Es wurden keine mehrfachen Login-Namen in der Datei /etc/passwd gefunden.\n';
  }

  cmd = 'getent passwd | cut -f3 -d: | uniq -d';
  Mult_UIDs = ssh_cmd(socket:sock, cmd:cmd);
  if( Mult_UIDs ){
    SYS_1_3_A2 += 'Folgende UIDs sind mehrfach in der Datei /etc/passwd enthalten:\n' + Logins + '\n\n';
  }else{
    SYS_1_3_A2 += 'Es wurden keine mehrfachen UIDs in der Datei /etc/passwd gefunden.\n';
  }

  cmd = 'getent group | cut -d: -f3 | uniq -c -d';
  Mult_GIDs = ssh_cmd(socket:sock, cmd:cmd);
  if( Mult_GIDs ){
    SYS_1_3_A2 += 'Folgende GIDs sind mehrfach in der Datei /etc/group enthalten:\n' + Logins + '\n\n';
  }else{
    SYS_1_3_A2 += 'Es wurden keine mehrfachen GIDs in der Datei /etc/group gefunden.\n';
  }
}

cmd = 'cat /etc/group | cut -d : -f 3';
Group = ssh_cmd(socket:sock, cmd:cmd);
if( "permission denied" >< tolower(Group) || ! Group ){
  SYS_1_3_A2 += 'Die Datei "/etc/groups" konnte nicht gelesen werden (Keine Berechtigung).\n\n';
}else{
  GIDs = split(Group, keep:FALSE);
  
  cmd = 'cat /etc/passwd';
  Users = ssh_cmd(socket:sock, cmd:cmd);
  if( "permission denied" >< tolower(Users) || ! Users ){
    SYS_1_3_A2 += 'Die Datei "/etc/passwd" konnte nicht gelesen werden (Keine Berechtigung).\n';
  }else{
    Users = split(Users, keep:FALSE);
    foreach User (Users) {
      User = split(User, sep:':', keep:FALSE);
      if( ! in_array(search:User[3], array:GIDs) ){
        NoGID += User[0] + ' : ' + User[3] + '\n';
      }
    }
  }
  if( NoGID ){
    SYS_1_3_A2 += 'Folgende Benutzer besitzen eine GID, welche nicht in der Datei /etc/group vorhanden ist (User:GID):\n' + NoGID + '\n';
  }else{
    SYS_1_3_A2 += 'Es wurden keine Benutzer mit einer ungültigen GID gefunden.\n';
  }
}

cmd = 'getent group';
GroupMembers = ssh_cmd(socket:sock, cmd:cmd);
if( "permission denied" >< tolower(GroupMembers) ){
  SYS_1_3_A2 += 'Die Datei "/etc/groups" konnte nicht gelesen werden (Keine Berechtigung).\n\n';
}else if( GroupMembers ){
  GroupMembers = split(GroupMembers, keep:FALSE);
  foreach Group (GroupMembers) {
    Group_Split = split(Group, sep:':', keep:FALSE);
    if( max_index(Group_Split) >= 4 ){
      Groups += Group + '\n';
    }
  }  
  SYS_1_3_A2 += 'Folgende Mitgliedern von Gruppen existieren in der Datei /etc/groups:\n' + Groups + '\n';
}else{
  SYS_1_3_A2 += 'Es wurden keine Gruppen in der Datei /etc/groups mit Mitgliedern gefunden.\n\n';
}

# SYS.1.3.A3 Automatisches Einbinden von Wechsellaufwerken
SYS_1_3_A3 = 'SYS.1.3.A3  Automatisches Einbinden von Wechsellaufwerken:\n';
cmd = 'dpkg -s autofs';
Autofs = ssh_cmd(socket:sock, cmd:cmd);
if( "not installed" >< tolower(Autofs) ){
  SYS_1_3_A3 += 'Das Paket "autofs" ist auf dem Host nicht installiert.\n\n';
}else if( ! Autofs ){
  SYS_1_3_A3 += 'Es konnte nicht ermittelt werden, ob das Paket "autofs" auf dem Host installiert ist.\n\n';
}else{
  SYS_1_3_A3 += 'Das Paket "autofs" scheint auf dem Host installiert zu sein. Dies kann automatisches Einbinden von Wechsellaufwerken zur Folge haben.\n\n';
}


# SYS.1.3.A4 Schutz von Anwendungen
SYS_1_3_A4 = 'SYS.1.3.A4  Schutz von Anwendungen:\n';
cmd = 'cat /proc/sys/kernel/randomize_va_space';
ASLR = ssh_cmd(socket:sock, cmd:cmd);
if( ASLR == '2' ){
  SYS_1_3_A4 += 'ASLR ist aktiviert (randomize_va_space = 2)\n';
}else if( ASLR == '1' ){
  SYS_1_3_A4 += 'ASLR ist aktiviert (randomize_va_space = 1). Es sollte überlegt werden, diesen auf 2 zu setzen.\n';
}else{
  SYS_1_3_A4 += 'ASLR ist nicht aktiviert.\n';
}

cmd = 'dmesg | grep NX | grep protection';
DEPNX = ssh_cmd(socket:sock, cmd:cmd);
if( ! DEPNX ){
  cmd = 'cat /var/log/messages | grep NX | grep protection';
  var_messages_DEPNX = ssh_cmd(socket:sock, cmd:cmd);
  if( "permission denied" >< tolower(var_messages_DEPNX) ){
    SYS_1_3_A4 += 'Die Datei /var/log/messages konnte nicht gelesen werden (Keine Berechtigung).\n';
  }else{
    if( 'active' >< tolower(DEPNX) ){
      SYS_1_3_A4 += 'DEP/NX ist aktiviert.\n';
    }else{
      SYS_1_3_A4 += 'DEP/NX ist nicht aktiviert.\n';
    }
  }
}else if( 'active' >< tolower(DEPNX) ){
  SYS_1_3_A4 += 'DEP/NX ist aktiviert.\n';
}else{
  SYS_1_3_A4 += 'DEP/NX ist nicht aktiviert.\n';
}
SYS_1_3_A4 += '\n';

# SYS.1.3.A5 Sichere Installation von Software-Paketen
SYS_1_3_A5 = 'SYS.1.3.A5 Sichere Installation von Software-Paketen:\n';
SYS_1_3_A5 += 'Diese Vorgabe kann nicht implementiert werden.\n\n';


# SYS.1.3.A6 Verwaltung von Benutzern und Gruppen
SYS_1_3_A6 = 'SYS.1.3.A6 Verwaltung von Benutzern und Gruppen:\n';
SYS_1_3_A6 += 'Es können nur die Zugriffsrechte der Dateien überprüft werden:\n';
cmd = 'ls -l /etc/passwd';
passwd_access = ssh_cmd(socket:sock, cmd:cmd);
passwd_access_correct = ereg(string:passwd_access, pattern:'-rw-r--r--.+root');
cmd = 'ls -l /etc/group';
group_access = ssh_cmd(socket:sock, cmd:cmd);
group_access_correct = ereg(string:group_access, pattern:'-rw-r--r--.+root');
cmd = 'ls -l /etc/sudoers';
sudoers_access = ssh_cmd(socket:sock, cmd:cmd);
sudoers_access_correct = ereg(string:sudoers_access, pattern:'-r--r-----.+root');

if( passwd_access_correct == '1' ){
  SYS_1_3_A6 += 'Der Besitzer der Datei "/etc/passwd" ist "root". Andere Benutzer besitzen lediglich Leserechte.\n';
}else{
  SYS_1_3_A6 += 'Entweder ist "root" nicht der Besitzer der Datei "/etc/passwd" und / oder die Zugriffsrechte sind nicht richtig vergeben.\n';
}
SYS_1_3_A6 += 'Folgende Benutzerrechte gelten für die Datei:\n' + passwd_access + '\n';
if( group_access_correct == '1' ){
  SYS_1_3_A6 += 'Der Besitzer der Datei "/etc/group" ist "root". Andere Benutzer besitzen lediglich Leserechte.\n';
}else{
  SYS_1_3_A6 += 'Entweder ist "root" nicht der Besitzer der Datei "/etc/group" und / oder die Zugriffsrechte sind nicht richtig vergeben.\n';
}
SYS_1_3_A6 += 'Folgende Benutzerrechte gelten für die Datei:\n' + group_access + '\n';
if( sudoers_access_correct == '1' ){
  SYS_1_3_A6 += 'Der Besitzer der Datei "/etc/sudoers" ist "root". Andere Benutzer besitzen lediglich Leserechte.\n';
}else{
  SYS_1_3_A6 += 'Entweder ist "root" nicht der Besitzer der Datei "/etc/sudoers" und / oder die Zugriffsrechte sind nicht richtig vergeben.\n';
}
SYS_1_3_A6 += 'Folgende Benutzerrechte gelten für die Datei:\n' + sudoers_access + '\n\n';


# SYS.1.3.A7 Zusätzliche Absicherung des Zugangs zum Single-User- und Wiederherstellungsmodus
SYS_1_3_A7 = 'SYS.1.3.A7 Zusätzliche Absicherung des Zugangs zum Single-User- und Wiederherstellungsmodus:\n';
SYS_1_3_A7 += 'Diese Vorgabe kann nicht implementiert werden.\n\n';

# SYS.1.3.A8 Verschlüsselter Zugriff über Secure Shell
SYS_1_3_A8 = 'SYS.1.3.A8 Verschlüsselter Zugriff über Secure Shell:\n';
cmd = 'dpkg -s telnet';
telnet = ssh_cmd(socket:sock, cmd:cmd);
if( "status: install ok installed" >< tolower(telnet) ){
  SYS_1_3_A8 += 'Das Paket "telnet" ist auf dem Host installiert. Dies sollte deinstalliert werden.\n';
}else{
  SYS_1_3_A8 += 'Das Paket "telnet" ist auf dem Host nicht installiert.\n';
}

cmd = 'dpkg -s telnetd';
telnet = ssh_cmd(socket:sock, cmd:cmd);
if( "status: install ok installed" >< tolower(telnet) ){
  SYS_1_3_A8 += 'Das Paket "telnetd" ist auf dem Host installiert. Dies sollte deinstalliert werden.\n\n';
}else{
  SYS_1_3_A8 += 'Das Paket "telnetd" ist auf dem Host nicht installiert.\n\n';
}

# SYS.1.3.A9 Absicherung des Bootvorgangs
SYS_1_3_A9 = 'SYS.1.3.A9 Absicherung des Bootvorgangs:\n';
SYS_1_3_A9 += 'Diese Vorgabe kann nicht implementiert werden.\n\n';


# SYS.1.3.A10 Verhinderung der Ausbreitung bei der Ausnutzung von Schwachstellen
SYS_1_3_A10 = 'SYS.1.3.A10 Verhinderung der Ausbreitung bei der Ausnutzung von Schwachstellen:\n'; 
AppArmor_Basic = get_kb_item("GSHB/AppArmor_Basic");
AppArmor_Utils = get_kb_item("GSHB/AppArmor_Utils");
if( AppArmor_Basic == '1' ) {
  SYS_1_3_A10 += 'Das Paket "apparmor" ist auf dem Host installiert.\n';
}else{
  SYS_1_3_A10 += 'Das Paket "apparmor" ist auf dem Host nicht installiert.\n';
}

if( AppArmor_Utils != '1' ){
  SYS_1_3_A10 += 'Das Paket "apparmor-utils ist nicht auf dem Host installiert. Für eine weitere Analyse von AppArmor muss dieses Paket installiert sein.\n';
}else{
  AppArmor_Status = get_kb_item("GSHB/AppArmor_Status");
  if( AppArmor_Status == "error" || ! AppArmor_Status){
    SYS_1_3_A10 += 'AppArmor scheint installiert zu sein. Der Befehl "aa-status" ist jedoch nicht bekannt.\nDies kann an fehlenden Berechtigungen liegen.\n';
  }else{
    SYS_1_3_A10 += 'AppArmor ist in folgendem Zustand:\n' + AppArmor_Status + '\n\n';
  }
}

SELinux_Basics = get_kb_item("GSHB/SeLinux_Basics");
SELinux_Utils = get_kb_item("GSHB/SeLinux_Utils");
if( SELinux_Basics == '1' ){
  SYS_1_3_A10 += 'Das Paket "selinux-bascis" ist auf dem Host installiert.\n';
}else{
  SYS_1_3_A10 += 'Das Paket "selinux-basics" ist auf dem Host nicht installiert.\n';
}

if( SELinux_Utils != '1' ){
  SYS_1_3_A10 += 'Das Paket "selinux-utils" ist auf dem Host nicht installiert. Für eine weitere Analyse von SELinux muss dieses Paket installiert sein.\n';
}else{
  SYS_1_3_A10 += 'Das Paket "selinux-utils" ist auf dem Host installiert.\n';
  sestatus = get_kb_item("GSHB/SeLinux_Status");
  if( ! sestatus || sestatus == "error" ){
    SYS_1_3_A10 += 'Der Befehl "sestatus" ist dem System nicht bekannt. Es können keine Informationen über SELinux gefunden werden.\n';
  }else{
    SYS_1_3_A10 += 'SELinux ist in folgendem Zustand:\n' + sestatus + '\n\n';
  }
}
if( "DEB8" >< debian_version || "DEB9" >< debian_version ){
    SYS_1_3_A10 += 'SELinux wird ab Debian 8 (Jessie) nicht mehr komplett unterstützt.\n';
    SYS_1_3_A10 += 'Das Paket "selinux-policy-default" kann für diese Distributionen nicht aus offiziellen Quellen bezogen werden.\n';
}
SYS_1_3_A10 += 'Es wird lediglich "AppArmor" und "SELinux" getestet.\n\n';

# SYS.1.3.A11 Einsatz der Sicherheitsmechanismen von NFS
SYS_1_3_A11 = 'SYS.1.3.A11 Einsatz der Sicherheitsmechanismen von NFS:\n';
cmd = 'dpkg -s nfs-common nfs-kernel-server';
NFS_ = ssh_cmd(socket:sock, cmd:cmd);
NFS_Common = ereg(string:NFS_, pattern:'Package: nfs-common\nStatus: install ok installed', multiline:TRUE);
NFS_Kernel_Server = ereg(string:NFS_, pattern:'Package: nfs-kernel-server\nStatus: install ok installed', multiline:TRUE);
if( NFS_Common != '1' ){
  SYS_1_3_A11 += 'Das Paket "nfs-common" ist nicht auf dem Host installiert. Dies sollte auf einem NFS Server installiert sein.\n';
}else{
  SYS_1_3_A11 += 'Das Paket "nfs-common" ist auf dem Host installiert.\n';
}
if( NFS_Kernel_Server != '1' ){
  SYS_1_3_A11 += 'Das Paket "nfs-kernel-server" ist nicht auf dem Host installiert.\n';
  SYS_1_3_A11 += 'Es wird davon ausgegangen, dass es sich bei dem Host nicht um ein NFS Server handelt.\n\n';
}else{
  cmd = 'cat /etc/exports';
  exports = ssh_cmd(socket:sock, cmd:cmd);
  if( "no such file or directory" >< tolower(exports) || ! exports ){
    SYS_1_3_A11 += 'Die Datei "/etc/exports" konnte nicht gelesen werden.\n';
  }else{
    SYS_1_3_A11 += 'Folgende mountbaren Verzeichnisse sind in der Datei "/etc/exports" gelistet:\n' + exports + '\n\n';
  }
  if( "permission denied" >< tolower(exports) ){
    SYS_1_3_A11 += 'Die Datei "/etc/exports" konnte nicht gelesen werden (keine Berechtigung).\n';
  }
  cmd = 'cat /etc/dfs/fstab';
  fstab = ssh_cmd(socket:sock, cmd:cmd);
  if( "no such file or directory" >< tolower(fstab) || ! fstab ){
    SYS_1_3_A11 += 'Die Datei "/etc/dfs/fstab" konnte nicht gelesen werden.\n';
  }else{
    SYS_1_3_A11 += 'Folgende mountbaren Verzeichnisse sind in der Datei "/etc/fstab" gelistet:\n' + exports + '\n\n';
  }
  if( "permission denied" >< tolower(fstab) ){
    SYS_1_3_A11 += 'Die Datei "/etc/dfs/fstab" konnte nicht gelesen werden (keine Berechtigung).\n';
  }
  SYS_1_3_A11 += 'Es werden lediglich die mountbaren Verzeichnisse in "/etc/exports" und "/etc/dfs/fstab" gelistet.\n\n';
}

# SYS.1.3.A12 Einsatz der Sicherheitsmechanismen von NIS
SYS_1_3_A12 = 'SYS.1.3.A12 Einsatz der Sicherheitsmechanismen von NIS:\n';
cmd = 'dpkg -s nis';
NIS = ssh_cmd(socket:sock, cmd:cmd);
if( "'nis' is not installed and no information is available" >< NIS ){
  SYS_1_3_A12 += 'Das Paket "nis" ist nicht auf dem Host installiert.\n';
  SYS_1_3_A12 += 'Es wird davon ausgegangen, dass es sich bei dem Host nicht um ein NIS Server handelt.\n\n';
}else{
  cmd = 'cat /etc/passwd | grep "+::0:0:::"';
  passwd = ssh_cmd(socket:sock, cmd:cmd);
  if( passwd ){
    SYS_1_3_A12 += 'In der Datei "/etc/passwd" wurde der Eintrag "+::0:0:::" gefunden. Dieser sollte entfernt werden.\n';
  }else{
    SYS_1_3_A12 += 'Der Eintrag "+::0:0:::" wurde nicht in der Datei "/etc/passwd" gefunden.\n';
  }

  cmd = 'cat /etc/group | grep "+::0:0:::"';
  group = ssh_cmd(socket:sock, cmd:cmd);
  if( group ){
    SYS_1_3_A12 += 'In der Datei "/etc/group" wurde der Eintrag "+::0:0:::" gefunden. Dieser sollte entfernt werden.\n';
  }else{
    SYS_1_3_A12 += 'Der Eintrag "+::0:0:::" wurde nicht in der Datei "/etc/group" gefunden.\n';
  }
  SYS_1_3_A12 += 'Es werden lediglich die Dateien "/etc/passwd" und "/etc/group" auf den Eintrag "+::0:0:::" durchsucht.\n';

  cmd = 'cat /var/yp/securenets';
  YPSERV = ssh_cmd(socket:sock, cmd:cmd);
  if( "no such file or directory" >< tolower(YPSERV) || ! YPSERV ){
    SYS_1_3_A12 += 'Die Datei "/var/yp/securenets" konnte nicht gefunden werden.\n';
    SYS_1_3_A12 += 'Diese sollte konfiguriert werden, damit nur Anfragen von festgelegten Rechnern beantwortet werden.\n\n';
  }else{
    SYS_1_3_A12 += 'In der Datei "/var/yp/securenets" sind folgende Regeln festgelegt:\n' + YPSERV + '\n\n';
  }
}


# SYS.1.3.A13 Zusätzlicher Schutz der priviligierten Anmeldeinformationen (CI)
SYS_1_3_A13 = 'SYS.1.3.A13 Zusätzlicher Schutz der priviligierten Anmeldeinformationen (CI):\n';
cmd = "cat /etc/ssh/sshd_config | grep -v '^#' | grep -v -e '^$'";
AdminLock = ssh_cmd(socket:sock, cmd:cmd);
if( "permission denied" >< tolower(AdminLock) || ! AdminLock ){
  SYS_1_3_A13 += 'Die Datei "/etc/ssh/sshd_config" konnte nicht gelesen werden (keine Berechtigung).\n';
}else{
  pattern = 'PermitRootLogin [a-z,A-Z,-]+';
  PermitRootLogin=eregmatch(string:AdminLock, pattern:pattern, multiline:TRUE);
  if( ! PermitRootLogin ){
    SYS_1_3_A13 += 'Der Eintrag "PermitRootLogin" ist nicht gesetzt in "/etc/ssh/sshd_config".\n';
    SYS_1_3_A13 += 'Dieser sollte auf "no" gesetzt sein, um eine Anmeldung von root über SSH am System zu verhindern.\n';
  }else{
    PermitRootLogin=split(PermitRootLogin[0], sep:' ',keep:FALSE);
    if( PermitRootLogin[1] == 'no' ){
      SYS_1_3_A13 += 'Der Eintrag "PermitRootLogin" in der Datei "/etc/ssh/sshd_config" ist auf den Wert "no" gesetzt.\n';
      SYS_1_3_A13 += '"root" kann sich nicht direkt am System über SSH anmelden\n';
    }else{
      SYS_1_3_A13 += 'Der Eintrag "PermitRootLogin" ist auf den Wert "' + PermitRootLogin[1] + '" gesetzt.\n';
      SYS_1_3_A13 += 'Dieser sollte auf "no" gesetzt sein, um eine Anmeldung von root über SSH am System zu verhindern.\n';
    }
  }
  pattern = 'MaxAuthTries [0-9]+';
  MaxAuthTries=eregmatch(string:AdminLock, pattern:pattern, multiline:TRUE);
  if( ! MaxAuthTries ){
    SYS_1_3_A13 += 'Der Eintrag "MaxAuthTries" ist nicht gesetzt in "/etc/ssh/sshd_config".\n';
    SYS_1_3_A13 += 'Dieser sollte auf einen angemessenen Wert gesetzt sein, um Brute-Force-Angrille über SSH am System zu verhindern.\n';
  }else{
    MaxAuthTries=split(MaxAuthTries[0], sep:' ',keep:FALSE);
    if( MaxAuthTries[1] > '0' && MaxAuthTries [1] <= '5' ){
      SYS_1_3_A13 += 'Der Eintrag "MaxAuthTries" in der Datei "/etc/ssh/sshd_config" ist auf den Wert "' + MaxAuthTries[1] + '" gesetzt.\n';
      SYS_1_3_A13 += 'Dieser Wert scheint angemessen zu sein. Dieser Wert sollte mit evtl. internen Policies übereinstimmen.\n';
    }else{
      SYS_1_3_A13 += 'Der Eintrag "MaxAuthTries" ist auf den Wert "' + MaxAuthTries[1] + '" gesetzt.\n';
      SYS_1_3_A13 += 'Dieser scheint unangemessen hoch zu sein. Um Brute-Force-Angriffe zu verhindern, sollte dieser verringert werden.\n';
      SYS_1_3_A13 += 'Dieser sollte ebenfalls mit evtl. internen Policies übereinstimmen.\n';
    }
  }
}
SYS_1_3_A13 += 'Es werden lediglich die Einträge "PermitRootLogin" und "MaxAuthTries" in der Datei "/etc/ssh/sshd_config" überprüft.\n\n';

# SYS.1.3.A14 Verhinderung des Ausspähens von System- und Benutzerinformationen (C)
SYS_1_3_A14 = 'SYS.1.3.A14 Verhinderung des Ausspähens von System- und Benutzerinformationen (C):\n';
filenames = ["/etc/issue", 
          "/proc/version",
          "/etc/debian_version",
          "/proc/sys/kernel/ostype",
          "/proc/sys/kernel/hostname",
          "/proc/sys/kernel/osrelease",
          "/proc/sys/kernel/version",
          "/proc/sys/kernel/domainname",
          "/var/log/auth.log",
          "/var/log/daemon.log",
          "/var/log/dmesg",
          "/var/log/kern.log",
          "/var/log/messages",
          "/var/log/syslog",
          "/var/log/user.log"];

foreach file (filenames) {
  cmd = "ls -lah " + file + " | cut -d' ' -f 1,3,4";
  AccessRights = ssh_cmd(socket:sock, cmd:cmd);
  if( "no such file" >< AccessRights ){
    SYS_1_3_A14 += 'Die Datei "' + file + '" konnte nicht gefunden werden.\n';
  }else{
    AccessRights = split(AccessRights, sep:' ', keep:FALSE);
    SYS_1_3_A14 += 'Die Datei "' + file + '" hat folgende Rechte: ' + AccessRights[0] + ' und gehört dem User: ' + AccessRights[1] + ', zugehörig der Gruppe: ' + AccessRights[2] + '.\n';
  }
}
SYS_1_3_A14 += '\n';

# SYS.1.3.A15 Zusätzliche Absicherung des Bootvorgangs (CIA)
SYS_1_3_A15 = 'SYS.1.3.A15 Zusätzliche Absicherung des Bootvorgangs (CIA):\n';
SYS_1_3_A15 += 'Diese Vorgabe kann nicht implementiert werden.\n\n';

# SYS.1.3.A16 Zusätzliche Verhinderung der Ausbreitung bei der Ausnutzung von Schachstellen (CI)
SYS_1_3_A16 = 'SYS.1.3.A16 Zusätzliche Verhinderung der Ausbreitung bei der Ausnutzung von Schwachstellen (CI):\n';
SYS_1_3_A16 += 'Diese Vorgabe kann nicht implementiert werden.\n\n';


# SYS.1.3.A17 Zusätzlicher Schutz des Kernels (CI)
SYS_1_3_A17 = 'SYS.1.3.A17 Zusätzlicher Schutz des Kernels (CI):\n';
SYS_1_3_A17 += 'Diese Vorgabe kann nicht implementiert werden.\n\n';

message += 'Basis-Absicherung:\n\n' + SYS_1_3_A1 + SYS_1_3_A2 + SYS_1_3_A3 + SYS_1_3_A4 + SYS_1_3_A5;
LEVEL = get_kb_item("GSHB/level");
if( LEVEL == 'Standard' || 'Kern'){
  message += '\n\nStandard-Absicherung:\n\n' + SYS_1_3_A6 + SYS_1_3_A7 + SYS_1_3_A8 + SYS_1_3_A9 + SYS_1_3_A10 + SYS_1_3_A11 + SYS_1_3_A12;
}
if( LEVEL == 'Kern' ){
  message += '\n\nKern-Absicherung:\n\n' + SYS_1_3_A13 + SYS_1_3_A14 + SYS_1_3_A15 + SYS_1_3_A16 + SYS_1_3_A17;
}

log_message(port:0, data: message);

exit(0);
