##############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_SYS.2.3.nasl 8318 2018-01-08 09:27:29Z emoss $
#
# IT-Grundschutz Baustein: SYS.2.3 Clients unter Unix
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
  script_oid("1.3.6.1.4.1.25623.1.0.109038");
  script_version("$Revision: 8318 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-08 10:27:29 +0100 (Mon, 08 Jan 2018) $");
  script_tag(name:"creation_date", value:"2017-12-19 15:30:28 +0100 (Tue, 19 Dec 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name('SYS.2.3 Clients unter Unix');
  script_xref(name:"URL", value:" https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/bausteine/SYS/SYS_2_3_Clients_unter_Unix.html ");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_dependencies("GSHB/GSHB_SSH_prev_root_login.nasl", "GSHB/GSHB_SSH_AppArmor_SeLinux.nasl",
      "GSHB/GSHB_SSH_quota.nasl");
  script_mandatory_keys("ssh/login/packages", "Compliance/Launch/GSHB-ITG");
  script_tag(name:"summary", value:"Zielsetzung dieses Bausteins ist der Schutz von Informationen,
      die auf Unix-Clients erstellt, bearbeitet, gespeichert oder versendet werden");
  exit(0);
}

include("ssh_func.inc");
include("misc_func.inc");

port = kb_ssh_transport();
host_ip = get_host_ip();

sock = ssh_login_or_reuse_connection();
if( !sock ) {
  error = get_ssh_error();
  if( !error ){
    error = "No SSH Port or Connection!";
    log_message(port:port, data:error);
    exit(0);
  }
}

Distribution = get_kb_item("ssh/login/release");
if( ! Distribution ){
  log_message(data:'Es konnte keine Linux-Distribution erkannt werden.\n', port:0);
  exit(0);
}



# SYS.2.3.A1 Authentisierung von Administratoren und Benutzer [Benutzer]
SYS_2_3_A1 = 'SYS.2.3.A1 Authentisierung von Administratoren und Benutzer:\n';
SECURETTY = get_kb_item("GSHB/securetty/nonconsole");
SSHDCONFIG = get_kb_item("GSHB/sshdconfig/PermitRootLogin");
LOGINDEFS = get_kb_item("GSHB/logindefs/syslogsuenab");
NFSEXPORTS = get_kb_item("GSHB/nfsexports");
NOROOTSQUASH = get_kb_item("GSHB/nfsexports/norootsquash");
ROOTSQUASH = get_kb_item("GSHB/nfsexports/rootsquash");
PERM_SECURETTY = get_kb_item("GSHB/securetty/perm");
PERM_SSHDCONFIG = get_kb_item("GSHB/sshdconfig/perm");
PERM_LOGINDEFS = get_kb_item("GSHB/logindefs/perm");

if( SECURETTY == "nocat" || SSHDCONFIG == "nocat" ||
    LOGINDEFS == "nocat" || NFSEXPORTS == "nocat" ){
  SYS_2_3_A1 += 'Der Befehl "cat" ist auf dem System unbekannt. Die Einstellungen
    kontnen nicht gelesen werden.\n';
}else{
  if( SECURETTY == "none" ){
    SYS_2_3_A1 += 'Die Datei "/etc/securetty" konnte nicht gefunden werden.
      Administratoren können sich als root anmelden.
      Dies sollte verhindert werden.\n';
  }else if( SECURETTY == "noperm" ){
    SYS_2_3_A1 += 'Keine Berechtigung zum Lesen der Datei "/etc/securetty".\n';
  }else if( SECURETTY == "secure" ){
    SYS_2_3_A1 += 'Die Datei "/etc/securetty" existiert und ist leer. Zugang zu
      "root" wird auf Single-User-Mode oder Programme, die nicht von "pam_securetty"
      beschränkt werden (z.B. su, sudo, ssh, scp, sftp), begrenzt.\n';
  }else if( ! SECURETTY ){
    SYS_2_3_A1 += 'Ein Fehler trat auf beim Lesen von "/etc/securetty".\n';
  }else{
    SYS_2_3_A1 += 'Folgende zu entfernende Einträge sind in der Datei
      "etc/securetty" vorhanden:\n';
    SYS_2_3_A1 += SECURETTY;
  }

  if( SSHDCONFIG == "noperm" ){
    SYS_2_3_A1 += 'Keine Berechtigung zum Lesen der Datei "/etc/ssh/sshd_config".\n';
  }else if( SSHDCONFIG == "norootlogin" ){
    SYS_2_3_A1 += 'Beim Testen des Systems wurde festgestellt, dass
      PermitRootLogin in der Datei /etc/ssh/sshd_config auf no gesetzt ist.\n';
  }else if( SSHDCONFIG == "rootlogin" ){
    SYS_2_3_A1 += 'Der Eintrag "PermitRootLogin" in der Datei "/etc/ssh/sshd_config"
      auf "yes" gesetzt. Der Wert sollte, wenn möglich, auf "no" geändert werden.\n';
  }

  if( LOGINDEFS >< "noperm" ){
    SYS_2_3_A1 += 'Keine Berechtigung zum Lesen der Datei "/etc/login.defs"\n';
  }else if( LOGINDEFS == "syslogsuenab" ){
    SYS_2_3_A1 += 'Der Eintrag "SYSLOG_SU_ENAB" ist in der Datei "/etc/login.defs"
      auf "yes" gesetzt.\n';
  }else if( LOGINDEFS == "nosyslogsuenab" ){
    SYS_2_3_A1 += 'Der Eintrag "SYSLOG_SU_ENAB" ist in der Datei "/etc/login.defs"
      auf "no" gesetzt. Der Wert sollte, wenn möglich, auf "yes" geändert werden.\n';
  }

  if( NFSEXPORTS >< "noperm" ){
    SYS_2_3_A1 += 'Keine Berechtigung zum Lesen der Datei "/etc/exports".\n';
  }else if( NOROOTSQUASH != "none" ){
    SYS_2_3_A1 += 'Beim Testen des Systems wurde festgestellt, dass der Eintrag
      "root_squash" in der Datei "/etc/exports" bei folgenden Einträgen fehlt:\n';
    SYS_2_3_A1 += NOROOTSQUASH +'\n';
  }else if( NOROOTSQUASH == "none" && ROOTSQUASH != "none" ){
    SYS_2_3_A1 += 'Der Eintrag "root_squash" ist in der Datei "/etc/exports" bei
      allen Einträgen gesetzt.\n';
  }else if( NOROOTSQUASH == "none" && ROOTSQUASH == "none" ){
    SYS_2_3_A1 += 'Es gibt keine Einträge/Freigaben in der Datei "/etc/exports".\n';
  }

  if( PERM_SECURETTY != "none" ){
    if( PERM_SECURETTY =~ "-rw-(r|-)--(r|-)--.*"){
      SYS_2_3_A1 += 'Für die Datei "/etc/securetty" wurden folgende korrekte
        Sicherheitseinstellungen festgestellt:\n' + PERM_SECURETTY + '\n';
    }else{
      SYS_2_3_A1 += 'Für die Datei "/etc/securetty" wurden folgende fehlerhafte
        Sicherheitseinstellungen festgestellt: ' + PERM_SECURETTY;
      SYS_2_3_A1 += '\nBitte ändern Sie diese auf "-rw-r--r--".\n';
    }
  }

  if( PERM_SSHDCONFIG != "none" ){
    if( PERM_SSHDCONFIG =~ "-rw-(r|-)--(r|-)--.*" ){
      SYS_2_3_A1 += 'Für die Datei "/etc/ssh/sshd_config" wurden folgende korrekte
        Sicherheitseinstellungen festgestellt: ' + PERM_SSHDCONFIG + '\n';
    }else{
      SYS_2_3_A1 += 'Für die Datei "/etc/ssh/sshd_config" wurden folgende fehlerhafte
        Sicherheitseinstellungen festgestellt: ' + PERM_SSHDCONFIG;
      SYS_2_3_A1 += '\nBitte ändern Sie diese auf "-rw-r--r--".\n';
    }
  }

  if( PERM_LOGINDEFS != "none" ){
    if( PERM_LOGINDEFS =~ "-rw-(r|-)--(r|-)--.*" ){
      SYS_2_3_A1 += 'Für die Datei "/etc/login.defs" wurden folgende korrekte
        Sicherheitseinstellungen festgestellt: ' + PERM_LOGINDEFS + '\n \n';
    }else{
      SYS_2_3_A1 += 'Für die Datei "/etc/login.defs" wurden folgende fehlerhafte
        Sicherheitseinstellungen festgestellt: ' + PERM_LOGINDEFS;
      SYS_2_3_A1 += '\nBitte ändern Sie diese auf "-rw-r--r--".\n';
    }
  }
}

EnableSudo = ssh_cmd(socket: sock, cmd: "dpkg -s sudo");
if( "status: install ok installed" >< tolower(EnableSudo) ){
  SYS_2_3_A1 += 'Das Paket "sudo" ist installiert. Für Systemadministrationsaufgaben
    sollte "sudo" verwendet werden.\n\n';
}else{
  SYS_2_3_A1 += 'Das Paket "sudo" ist nicht installiert. Für Systemadministrationsaufgaben
    sollte "sudo" oder eine geeignete Alternative mit einer geeigneten Protokollierung
    genutzt werden.\n\n';
}


# SYS.2.3.A2 Auswahl einer geeigneten Distribution
SYS_2_3_A2 += 'SYS.2.3.A2 Auswahl einer geeigneten Distribution:\n';
if( get_kb_item("ssh/login/gentoo") ){
  SYS_2_3_A2 += 'Die erkannte Distribution "Gentoo" ist ein Rolling-Release-Modell.
    Solche Distributionen sollten nicht verwendet werden.\n\n';
}else{
  SYS_2_3_A2 += 'Es konnte keine Distribution mit einem Rolling-Release-Modell
    erkannt werden. Erkanntes OS: ' + Distribution + '\n\n';
}


# SYS.2.3.A3 Cloud- und Online-Inhalte
SYS_2_3_A3 += 'SYS.2.3.A3 Cloud- und Online-Inhalte:\n';
SYS_2_3_A3 += 'Diese Maßnahme kann nicht implementiert werden.\n\n';

# SYS.2.3.A4 Einspielen von Updates und Patches
SYS_2_3_A4 = 'SYS.2.3.A4 Einspielen von Updates und Patches:\n';
LivepatchEnabled = ssh_cmd(socket:sock, cmd:"ls -l /sys/kernel/ | grep livepatch");
if( ! LivepatchEnabled ){
  SYS_2_3_A4 += 'Live-Patching des Kernels ist nicht aktiviert.\n';
  Uptime = ssh_cmd(socket:sock, cmd:"uptime -s");
  if( "command not found" >< Uptime ){
    SYS_2_3_A4 += 'Fehler: Die Betriebszeit des Systems konnte nicht ermittelt werden
      (Befehl unbekannt: "uptime").\n\n';
  }else if ( Uptime ){
    SYS_2_3_A4 += 'Das System läuft seit: ' + Uptime + '\n';
    SYS_2_3_A4 += 'Falls der Kernel seitdem aktualisiert wurde, sollte das System
      neu gestartet werden.\n\n';
  }else{
    SYS_2_3_A4 += 'Fehler: Die Betriebszeit des Systems konnte nicht ermittelt werden.\n\n';
  }
}else if( "no such file or directory" >< LivepatchEnabled ){
  SYS_2_3_A4 += 'Auf dem Host existiert "/sys/kernel" nicht.
    Der Status des Live-Patching kann nicht ermittelt werden.\n\n';
}else if( "permission denied" >< LivepatchEnabled ){
  SYS_2_3_A4 += 'Der Zugriff auf "/sys/kernel" wurde verweigert.
    Der Status des Live-Patching kann nicht ermittelt werden.\n\n';
}else{
  SYS_2_3_A4 += 'Libe-Patching des Kernels ist aktiviert. ';
  InstalledPatches = ssh_cmd(socket:sock, cmd:"ls -l /sys/kernel/livepatch/");
  if( InstalledPatches ){
    SYS_2_3_A4 += 'Folgende Patches sind installiert:\n' + InstalledPatches + '\n\n';
  }else{
    SYS_2_3_A4 += 'Es konnten keine installierten Patches gefunden werden.\n\n';
  }
}


# SYS.2.3.A5 Sichere Installation von Software-Paketen
SYS_2_3_A5 += 'SYS.2.3.A5 Sichere Installation von Software-Paketen:\n';
SYS_2_3_A5 += 'Diese Maßnahme kann nicht implementiert werden.\n\n';

# SYS.2.3.A6 Automatisches Einbinden von Wechsellaufwerken [Benutzer]
SYS_2_3_A6 = 'SYS.2.3.A6 Automatisches Einbinden von Wechsellaufwerken:\n';
Autofs = ssh_cmd(socket:sock, cmd:"dpkg -s autofs");
if( "not installed" >< tolower(Autofs) ){
  SYS_2_3_A6 += 'Das Paket "autofs" ist auf dem Host nicht installiert.\n';
}else if( ! Autofs ){
  SYS_2_3_A6 += 'Es konnte nicht ermittelt werden, ob das Paket "autofs"
    auf dem Host installiert ist.\n';
}else{
  SYS_2_3_A6 += 'Das Paket "autofs" scheint auf dem Host installiert zu sein.
    Dies kann automatisches Einbinden von Wechsellaufwerken zur Folge haben.\n';
}

Missing_Noexec = ssh_cmd(socket:sock, cmd:"grep -vE '^#|noexec' /etc/fstab");
if( "command not found" >< Missing_Noexec ){
  SYS_2_3_A6 += 'Fehler: Die Datei "/etc/fstab" konnte nicht gelesen werden
    (Befehl unbekannt: "awk")\n\n';
}else if( "permission denied" >< Missing_Noexec ){
  SYS_2_3_A6 += 'Fehler: Die Datei "/etc/fstab" konnte nicht gelesen werden
    (Fehlende Berechtigung)\n\n';
}else if( "no such file or directory" >< Missing_Noexec ){
  SYS_2_3_A6 += 'Fehler: Die Datei "/etc/fstab" existiert nicht.\n\n';
}else if( ! Missing_Noexec ){
    SYS_2_3_A6 += 'Es wurden keine Partitionen ohne die Option "noexec" gefunden.\n\n';
}else{
    SYS_2_3_A6 += 'Folgende Partitionen haben die "noexec" Option nicht gesetzt, 
               es sollten keine Wechseldatenträger darunter sein:\n' 
      + Missing_Noexec + '\n\n';
}

# SYS.2.3.A7 Restriktive Rechtevergabe auf Dateien und Verzeichnisse
SYS_2_3_A7 += 'SYS.2.3.A7 Restriktive Rechtevergabe auf Dateien und Verzeichnisse:\n';
GlobalDirectories = ssh_cmd(socket:sock, cmd:"find / -maxdepth 3 -type d -perm -777");
if( GlobalDirectories ){
  GlobalDirectories = split(GlobalDirectories, keep:FALSE);
  SYS_2_3_A7 += 'In folgenden Verzeichnissen haben alle Benutzer Schreibrechte:\n';
  foreach Dir (GlobalDirectories){
    if( "permission denied" >< tolower(Dir) ){
      continue;
    }else{
      cmd = "ls -ld " + Dir;
      Perm = ssh_cmd(socket:sock, cmd:cmd);
      StickyBit=ereg(string:Perm, pattern:"d[r,w,x,-]{8}t", icase:TRUE);
      if( StickyBit == '1' ){
        SYS_2_3_A7 += Dir + ' : Sticky-Bit ist gesetzt.\n';
      }else{
        SYS_2_3_A7 += Dir + ' : Sticky-Bit ist nicht gesetzt. Dies sollte gesetzt werden.\n';
      }
    }
  }
  SYS_2_3_A7 += '\n';
}else{
  SYS_2_3_A7 += 'Keine Verzeichnisse, in denen alle Benutzer Schreibrechte haben,
  gefunden.';
}


# SYS.2.3.A8 Einsatz von Techniken zur Rechtebeschränkung von Anwendungen
SYS_2_3_A8 = 'SYS.2.3.A8 Einsatz von Techniken zur Rechtebeschränkung von Anwendungen:\n';
SYS_2_3_A8 = 'SYS.1.3.A10 Verhinderung der Ausbreitung bei der Ausnutzung von Schwachstellen:\n'; 
AppArmor_Basic = get_kb_item("GSHB/AppArmor_Basic");
AppArmor_Utils = get_kb_item("GSHB/AppArmor_Utils");
if( AppArmor_Basic == '1' ) {
  SYS_2_3_A8 += 'Das Paket "apparmor" ist auf dem Host installiert.\n';
}else{
  SYS_2_3_A8 += 'Das Paket "apparmor" ist auf dem Host nicht installiert.\n';
}

if( AppArmor_Utils != '1' ){
  SYS_2_3_A8 += 'Das Paket "apparmor-utils ist nicht auf dem Host installiert. 
    Für eine weitere Analyse von AppArmor muss dieses Paket installiert sein.\n';
}else{
  AppArmor_Status = get_kb_item("GSHB/AppArmor_Status");
  if( AppArmor_Status == "error" || ! AppArmor_Status){
    SYS_2_3_A8 += 'AppArmor scheint installiert zu sein. Der Befehl "aa-status" ist jedoch nicht bekannt.
      Dies kann an fehlenden Berechtigungen liegen.\n';
  }else{
    SYS_2_3_A8 += 'AppArmor ist in folgendem Zustand:\n' + AppArmor_Status + '\n\n';
  }
}

SELinux_Basics = get_kb_item("GSHB/SeLinux_Basics");
SELinux_Utils = get_kb_item("GSHB/SeLinux_Utils");
if( SELinux_Basics == '1' ){
  SYS_2_3_A8 += 'Das Paket "selinux-bascis" ist auf dem Host installiert.\n';
}else{
  SYS_2_3_A8 += 'Das Paket "selinux-basics" ist auf dem Host nicht installiert.\n';
}

if( SELinux_Utils != '1' ){
  SYS_2_3_A8 += 'Das Paket "selinux-utils" ist auf dem Host nicht installiert.
    Für eine weitere Analyse von SELinux muss dieses Paket installiert sein.\n';
}else{
  SYS_2_3_A8 += 'Das Paket "selinux-utils" ist auf dem Host installiert.\n';
  sestatus = get_kb_item("GSHB/SeLinux_Status");
  if( ! sestatus || sestatus == "error" ){
    SYS_2_3_A8 += 'Der Befehl "sestatus" ist dem System nicht bekannt.
      Es können keine Informationen über SELinux gefunden werden.\n';
  }else{
    SYS_2_3_A8 += 'SELinux ist in folgendem Zustand:\n' + sestatus + '\n\n';
  }
}
    
SYS_2_3_A8 += 'Beachten Sie, dass SELinux aktuell nicht mehr für alle 
  Distributionen unterstützt wird. Das Paket "selinux-policy-default" 
  kann für diese Distributionen nicht aus offiziellen Quellen bezogen werden.\n\n';

# SYS.2.3.A9 Passwörter auf der Kommandozeile [Benutzer]
SYS_2_3_A9 = 'SYS.2.3.A9 Passwörter auf der Kommandozeile:\n';
SYS_2_3_A9 += 'Diese Maßnahme kann nicht implementiert werden.\n\n';

# SYS.2.3.A10 Absicherung des Bootvorgangs
SYS_2_3_A10 = 'SYS.2.3.A10 Absicherung des Bootvorgangs:\n';
GrubConf = ["/boot/grub/menu.lst",
  "/etc/grub.conf",
  "/boot/grub/grub.conf",
  "/etc/grub.cfg",
  "/boot/grub/grub.cfg"];

foreach file (GrubConf) {
  cmd = "cat " + file + ' | grep "password"';
  GrubConfFile = ssh_cmd(socket:sock, cmd:cmd);
  if( "no such file or directory" >< GrubConfFile ){
    continue;
  }else if( ! GrubConfFile ){
    GrubPasswd = "nicht aktiviert";
  }else{
    GrubPasswd = "aktiviert";
  }
}

if( GrubPasswd ){
  SYS_2_3_A10 += 'Ein Passwort für Grub ist ' + GrubPasswd + '.\n';
}else{
  SYS_2_3_A10 += 'Es wurde keine Grub-Konfigurationsdatei gefunden.\n';
}

UEFI = ssh_cmd(socket:sock, cmd:'ls -l /sys/firmware/ | grep "efi"');
if( ! UEFI ){
  SYS_2_3_A10 += 'UEFI wird nicht genutzt.\n\n';
}else{
  SYS_2_3_A10 += 'UEFI wird genutzt.\n';
  SecureBoot = ssh_cmd(socket:sock, cmd:"mokutil --sb-state");
  if( "command not found" >< SecureBoot ){
    SYS_2_3_A10 += 'Der Status von Secure Boot konnte nicht ermittelt werden.
      Secure Boot sollte aktiviert werden.\n\n';
  }else if( "enabled" >< SecureBoot ){
    SYS_2_3_A10 += 'Secure Boot ist aktiviert.\n\n';
  }else{
    SYS_2_3_A10 += 'Secure Boot ist nicht aktiviert. Dies sollte aktiviert werden.\n\n';
  }
}


# SYS.2.3.A11 Verhinderung der Überlastung der Festplatte
SYS_2_3_A11 = 'SYS.2.3.A11 Verhinderung der Überlastung der Festplatte:\n';
fstabQuota = get_kb_item("GSHB/quota/fstab");
aquotauser = get_kb_item("GSHB/quota/user");
aquotagroup = get_kb_item("GSHB/quota/group");

if( ! fstabQuota || fstabQuota == "none" ){
  SYS_2_3_A11 += 'Es wurde kein Eintrag "quota" in der Datei "/etc/fstab" gefunden.
    Quotas ist nicht aktiviert.\n';
}else if( fstabQuota == "nogrep" ){
  SYS_2_3_A11 += 'Der Befehl "grep" ist nicht bekannt. Die Datei "/etc/fstab"
    konnte nicht gelesen werden.\n';
}else{
  SYS_2_3_A11 += 'Folgende Partitionen sind mit "Quota" eingeschränkt:\n' + 
    fstabQuota + '\n';
}

if( ! aquotauser || aquotauser == "none" || aquotauser == "nols" ){
  SYS_2_3_A11 += 'Die Datei "/aquota.user" konnte nicht gefunden oder gelesen werden.
    Quotas ist nicht korrekt konfiguriert.\n';
}
if( ! aquotagroup || aquotagroup == "none" || aquotagroup == "nols" ){
  SYS_2_3_A11 += 'Die Datei "/aquota.group" konnte nicht gefunden oder gelesen werden.
    Quotas ist nicht korrekt konfiguriert.\n';
}
SYS_2_3_A11 += '\n';


# SYS.2.3.A12 Einsatz von Appliances als Clients
SYS_2_3_A12 = 'SYS.2.3.A12 Einsatz von Appliances als Clients:\n';
SYS_2_3_A12 += 'Diese Maßnahme kann nicht implementiert werden.\n\n';

# SYS.2.3.A13 Schutz vor unbefugten Anmeldungen (CIA)
SYS_2_3_A13 = 'SYS.2.3.A13 Schutz vor unbefugten Anmeldungen (CIA):\n';
Libpam_Google_Authenticator = ssh_cmd(socket:sock, cmd:"dpkg -s libpam-google-authenticator");
Libpam_Google_Authenticator = ereg(string:Libpam_Google_Authenticator,
    pattern:"install ok installed", multiline:TRUE);
if( Libpam_Google_Authenticator == "1" ){
  SYS_2_3_A13 += 'Das Paket "libpam_google_authenticator" für die Zwei-Faktor-Authentisierung
    ist installiert. Bitte überprüfen Sie manuell die Konfiguration.\n\n';
}else{
  SYS_2_3_A13 += 'Das Paket "libpam_google_authenticator" ist nicht installiert.
    Bitte stellen Sie sicher, dass eine geeignete Methode zur Zwei-Faktor-
    Authentisierung verwendet wird.\n\n';
}


# SYS.2.3.A14 Absicherung gegen Nutzung unbefugter Peripheriegeräte (CIA)
SYS_2_3_A14 = 'SYS.2.3.A14 Absicherung gegen Nutzung unbefugter Peripheriegeräte (CIA):\n';
cmd = 'cat /etc/sysctl.conf | grep -v "^#" | grep "kernel.modules_disabled=1"';
AutoloadKernelModules = ssh_cmd(socket:sock, cmd:cmd);

if( AutoloadKernelModules ){
  SYS_2_3_A14 += 'Neue Kernelmodule können nicht automatisch geladen und 
    aktiviert werden.\n\n';
}else{
  SYS_2_3_A14 += 'Neue Kernelmodule können automatisch geladen und aktiviert
    werden. Dies sollte unterbunden werden (Fügen Sie "kernel.modules_disabled=1" 
    zur sysctl.conf Datei hinzu).\n\n';
}


# SYS.2.3.A15 Zusätzlicher Schutz vor der Ausführung unerwünschter Dateien (CI)
SYS_2_3_A15 = 'SYS.2.3.A15 Zusätzlicher Schutz vor der Ausführung unerwünschter Dateien (CI):\n';
MntWithoutNoexec = ssh_cmd(socket:sock, cmd:'findmnt -l | grep rw | grep -v "noexec"');
if( "command not found" >< tolower(MntWithoutNoexec) || 
    "permission denied" >< tolower(MntWithoutNoexec) ){
  SYS_2_3_A15 += 'Fehler: Die gemounteten Partitionen und Verzeichnisse konnten
    nicht gelesen werden.\n\n';
}else if( MntWithoutNoexec ){
  SYS_2_3_A15 += 'Folgende Partitionen und Verzeichnisse sind ohne die Option
    "noexec" gemountet und tragen die "rw" Option:\n' + MntWithoutNoexec + '\n
    Diese sollten mit der "noexec"-Option gemountet werden.\n\n';
}else{
  SYS_2_3_A15 += 'Es konnten keine beschreibbaren Partitionen ohne die "noexec"
    Option gefunden werden.\n\n';
}


# SYS.2.3.A16 Zusätzliche Absicherung des Bootvorgangs (CIA)
SYS_2_3_A16 = 'SYS.2.3.A16 Zusätzliche Absicherung des Bootvorgangs (CIA):\n';
SYS_2_3_A16 += 'Diese Maßnahme kann nicht implementiert werden.\n\n';

# SYS.2.3.A17Zusätzliche Verhinderung der Ausbreitung bei der Ausnutzung von Schwachstellen (CI)
SYS_2_3_A17 = 'SYS.2.3.A17 Zusätzliche Verhinderung der Ausbreitung bei der Ausnutzung von Schwachstellen (CI):\n';
Seccomp = ssh_cmd(socket:sock, cmd:"dpkg -s seccomp");
if( "install ok installed" >< Seccomp ){
  SYS_2_3_A17 += 'Das Paket "seccomp" ist installiert. Die Benutzung sollte
    manuell überprüft werden.\n';
}else{
  SYS_2_3_A17 += 'Das Paket "seccomp" ist nicht installiert. Dies sollte installiert
    und manuell überprüft werden.\n';
}
SYS_2_3_A17 += 'Die Standardprofile bzw. -Regeln von "SELinux" oder "AppArmor" 
  sollten manuell überprüft werden.\n\n';


# SYS.2.3.A18 Zusätzlicher Schutz des Kernels (CI)
SYS_2_3_A18 = 'SYS.2.3.A18 Zusätzlicher Schutz des Kernels (CI):\n';
SYS_2_3_A18 += 'Diese Maßnahme kann nicht implementiert werden.\n\n';

# SYS.2.3.A19 Festplatten- oder Dateiverschlüsselung (CI)
SYS_2_3_A19 = 'SYS.2.3.A19 Festplatten- oder Dateiverschlüsselung (CI):\n';
SYS_2_3_A19 += 'Diese Maßnahme kann nicht implementiert werden.\n\n';

# SYS.2.3.A20 Abschaltung kritischer SysRq-Funktionen (CIA)
SYS_2_3_A20 = 'SYS.2.3.A20 Abschaltung kritischer SysRq-Funktionen (CIA):\n';
SysRq = ssh_cmd(socket:sock, cmd:"cat /proc/sys/kernel/sysrq");
if( "permission denied" >< tolower(SysRq) ){
  SYS_2_3_A20 += 'Fehler: Die Datei "/proc/sys/kernel/sysrq" konnte nicht gelesen 
    werden (Keine Berechtigung).\n\n';
}else if( "no such file or directory" >< tolower(SysRq) ||
    SysRq == "0" ){
  SYS_2_3_A20 += 'Die SysRq-Funktionen sind deaktiviert.\n\n';
}else if( SysRq >= "0" ){
  SYS_2_3_A20 += 'Einige SysRq-Funktionen sind aktiviert. Zur Sicherheit sollten
    diese deaktiviert werden.\n\n';
}else{
  SYS_2_3_A20 += 'Fehler: Ein ungültiger Wert wurde in der Datei 
    "/proc/sys/kernel/sysrq" gefunden.\n\n';
}

message += 'Basis-Absicherung:\n\n' + SYS_2_3_A1 + SYS_2_3_A2 + SYS_2_3_A3;
message += SYS_2_3_A4 + SYS_2_3_A5;
LEVEL = get_kb_item("GSHB/level");
if( LEVEL == 'Standard' || 'Kern'){
  message += '\n\nStandard-Absicherung:\n\n' + SYS_2_3_A6 + SYS_2_3_A7 + SYS_2_3_A8;
  message += SYS_2_3_A9 + SYS_2_3_A10 + SYS_2_3_A11 + SYS_2_3_A12;
}
if( LEVEL == 'Kern' ){
  message += '\n\nKern-Absicherung:\n\n' + SYS_2_3_A13 + SYS_2_3_A14 + SYS_2_3_A15;
  message += SYS_2_3_A16 + SYS_2_3_A17 + SYS_2_3_A18 + SYS_2_3_A19 + SYS_2_3_A20;
}

log_message(port:0, data: message);

ssh_close_connection();
exit(0);
