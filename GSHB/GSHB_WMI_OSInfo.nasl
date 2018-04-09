###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_WMI_OSInfo.nasl 9365 2018-04-06 07:34:21Z cfischer $
#
# Get OS Version, OS Type, OS Servicepack and OS Name over WMI (win)
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# Set in an Workgroup Environment under Vista with enabled UAC this DWORD to access WMI:
# HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\LocalAccountTokenFilterPolicy to 1
#
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

tag_summary = "Get OS Version, OS Type, OS Servicepack and OS Name over WMI (win)";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96999");
  script_version("$Revision: 9365 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:34:21 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");  
  script_name("Get OS Version, OS Type, OS Servicepack and OS Name over WMI (win)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("WMI/access_successful");
  script_dependencies("smb_login.nasl", "secpod_reg_enum.nasl", "gb_wmi_access.nasl");
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("wmi_os.inc");

host    = get_host_ip();
usrname = get_kb_item("SMB/login");
domain  = get_kb_item("SMB/domain");
if (domain){
  usrname = domain + '\\' + usrname;
}
passwd  = get_kb_item("SMB/password");
samba = get_kb_item("SMB/samba");

errorval = "none";
if(samba){
  set_kb_item(name:"WMI/WMI_WindowsDomain", value:errorval);
  set_kb_item(name:"WMI/WMI_WindowsDomainrole", value:errorval);
  set_kb_item(name:"WMI/WMI_OSVER", value:errorval);
  set_kb_item(name:"WMI/WMI_OSSP", value:errorval);
  set_kb_item(name:"WMI/WMI_OSTYPE", value:errorval);
  set_kb_item(name:"WMI/WMI_OSDRIVE", value:errorval);
  set_kb_item(name:"WMI/WMI_OSWINDIR", value:errorval);
  set_kb_item(name:"WMI/WMI_OSNAME", value:errorval);
  set_kb_item(name:"WMI/WMI_OS/log", value:"On the Target System runs Samba, it is not an Microsoft System.");
  exit(0);
}
if(!host || !usrname || !passwd){
  log_message("wmi_connect: WMI Connect failed.");
  set_kb_item(name:"WMI/WMI_WindowsDomain", value:errorval);
  set_kb_item(name:"WMI/WMI_WindowsDomainrole", value:errorval);
  set_kb_item(name:"WMI/WMI_OSVER", value:errorval);
  set_kb_item(name:"WMI/WMI_OSSP", value:errorval);
  set_kb_item(name:"WMI/WMI_OSTYPE", value:errorval);
  set_kb_item(name:"WMI/WMI_OSDRIVE", value:errorval);
  set_kb_item(name:"WMI/WMI_OSWINDIR", value:errorval);
  set_kb_item(name:"WMI/WMI_OSNAME", value:errorval);
  set_kb_item(name:"WMI/WMI_OS/log", value:"No Host, Username or Pasword");
  exit(0);
}


handle = wmi_connect(host:host, username:usrname, password:passwd);

if(!handle){
  log_message("wmi_connect: WMI Connect failed.");
  set_kb_item(name:"WMI/WMI_WindowsDomain", value:errorval);
  set_kb_item(name:"WMI/WMI_WindowsDomainrole", value:errorval);
  set_kb_item(name:"WMI/WMI_OSVER", value:errorval);
  set_kb_item(name:"WMI/WMI_OSSP", value:errorval);
  set_kb_item(name:"WMI/WMI_OSTYPE", value:errorval);
  set_kb_item(name:"WMI/WMI_OSDRIVE", value:errorval);
  set_kb_item(name:"WMI/WMI_OSWINDIR", value:errorval);
  set_kb_item(name:"WMI/WMI_OSNAME", value:errorval);
  set_kb_item(name:"WMI/WMI_OS/log", value:"wmi_connect: WMI Connect failed.");
  exit(0);
}

query1 = 'select Caption from Win32_OperatingSystem';
query2 = 'select Domain from Win32_ComputerSystem';
query3 = 'select DomainRole from Win32_ComputerSystem';
query4 = 'select OSArchitecture from Win32_OperatingSystem';

OSVER = wmi_os_version(handle:handle);
OSSP =  wmi_os_sp(handle:handle);
if (OSSP != 1){
    OSSP = eregmatch(pattern:"[0-9]", string:OSSP);
    OSSP = OSSP[0];
}else OSSP = "Without SP";

OSTYPE = wmi_os_type(handle:handle);

OSArchitecture = wmi_query(wmi_handle:handle, query:query4);
OSArchitecture = split(OSArchitecture, sep:'\n', keep:0);

OSNAME = wmi_query(wmi_handle:handle, query:query1);
OSNAME = split(OSNAME, sep:'\n', keep:0);
if (OSVER <= 6){
 OSNAME = split(OSNAME[1], sep:'|', keep:0);
 OSNAME = OSNAME[0];
}
else OSNAME = OSNAME[1];

Domain = wmi_query(wmi_handle:handle, query:query2);
Domain = split(Domain, sep:'\n', keep:0);
Domain = split(Domain[1], sep:'|', keep:0);
Domain = Domain[0];
windirpath = wmi_os_windir(handle:handle);

if (OSVER < 6){
val01 = split(windirpath, sep:"|", keep:0);
val02 = split(val01[4], sep:"\", keep:0);
OSDRIVE = val02[0];
}
else {
val01 = split(windirpath, sep:":", keep:0);
val04 = eregmatch(pattern:"[A-Z]$", string:val01[0]);
OSDRIVE = val04[0] + ":";
}

OSWINDIR = wmi_os_windir(handle:handle);
if (OSVER < '6.0')
{
  OSWINDIR = split(OSWINDIR, sep:"|", keep:0);
  OSWINDIR = ereg_replace(pattern:'\n', string:OSWINDIR[4], replace:'');
}
else
{
  OSWINDIR = split(OSWINDIR, sep:'\n', keep:0);
  OSWINDIR = OSWINDIR[1];
}

Domainrole = wmi_query(wmi_handle:handle, query:query3);
if (!Domainrole) Domainrole = "none";
else
{
  Domainrole = split(Domainrole, sep:'\n', keep:0);
  Domainrole = split(Domainrole[1], sep:'|', keep:0);
  Domainrole = Domainrole[0];
}
#Domainrole Definition:
#0 (0x0) Standalone Workstation
#1 (0x1) Member Workstation
#2 (0x2) Standalone Server
#3 (0x3) Member Server
#4 (0x4) Backup Domain Controller
#5 (0x5) Primary Domain Controller

if (!OSVER) OSVER = errorval;
if (!OSSP) OSSP = errorval;
if (!OSTYPE) OSTYPE = errorval;
if (!OSArchitecture[1]) OSArchitecture[1] = errorval;
if (!OSNAME) OSNAME = errorval;
if (!OSDRIVE) OSDRIVE = errorval;
if (!OSWINDIR) OSWINDIR = errorval;
if (!Domain) Domain = errorval;



set_kb_item(name:"WMI/WMI_WindowsDomain", value:Domain);
set_kb_item(name:"WMI/WMI_WindowsDomainrole", value:Domainrole);
set_kb_item(name:"WMI/WMI_OSVER", value:OSVER);
set_kb_item(name:"WMI/WMI_OSSP", value:OSSP);
set_kb_item(name:"WMI/WMI_OSTYPE", value:OSTYPE);
set_kb_item(name:"WMI/WMI_OSArchitecture", value:OSArchitecture[1]);
set_kb_item(name:"WMI/WMI_OSDRIVE", value:OSDRIVE);
set_kb_item(name:"WMI/WMI_OSWINDIR", value:OSWINDIR);
set_kb_item(name:"WMI/WMI_OSNAME", value:OSNAME);
set_kb_item(name:"WMI/WMI_OS/log", value:"ok");
wmi_close(wmi_handle:handle);

exit(0);
