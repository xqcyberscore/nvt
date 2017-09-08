###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_WMI_TerminalServerSettings.nasl 7076 2017-09-07 11:53:47Z teissa $
#
# Get Windows Terminal Server Settings
#
# Authors:
# Thomas Rotter <thomas.rotter@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# Set in an Workgroup Environment under Vista with enabled UAC this DWORD to access WMI:
# HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\LocalAccountTokenFilterPolicy to 1
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
  script_oid("1.3.6.1.4.1.25623.1.0.96213");
  script_version("$Revision: 7076 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-07 13:53:47 +0200 (Thu, 07 Sep 2017) $");
  script_tag(name:"creation_date", value:"2011-12-14 11:30:03 +0100 (Wed, 14 Dec 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");  
  script_name("Get Windows Terminal Server Settings");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_mandatory_keys("Tools/Present/wmi");
  script_dependencies("toolcheck.nasl", "GSHB_WMI_OSInfo.nasl");

  script_tag(name : "summary" , value : "The script reads the Windows Terminal Server Settings.");

  exit(0);
}

host    = get_host_ip();
usrname = get_kb_item("SMB/login");
domain  = get_kb_item("SMB/domain");
if (domain){
  usrname = domain + '\\' + usrname;
}
passwd  = get_kb_item("SMB/password");
OSVER = get_kb_item("WMI/WMI_OSVER");
    
if(!OSVER || OSVER >< "none"){
  error = get_kb_item("WMI/WMI_OS/log");
  set_kb_item(name:"WMI/TerminalService", value:"error");
  if (error)set_kb_item(name:"WMI/TerminalService/log", value:error);
  else set_kb_item(name:"WMI/TerminalService/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
  exit(0);
}

handle = wmi_connect(host:host, username:usrname, password:passwd);

if(!handle){
  set_kb_item(name:"WMI/TerminalService", value:"error");
  set_kb_item(name:"WMI/TerminalService/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  exit(0);
}

query = 'select * from Win32_TerminalServiceSetting';

TSS = wmi_query(wmi_handle:handle, query:query);

if(!TSS) TSS = "none";

set_kb_item(name:"WMI/TerminalService", value:TSS);


wmi_close(wmi_handle:handle);
exit(0);

