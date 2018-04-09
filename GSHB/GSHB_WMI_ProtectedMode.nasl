###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_WMI_ProtectedMode.nasl 9365 2018-04-06 07:34:21Z cfischer $
#
# Checks InternetExplorer Policy for Protected Mode over WMI (Windows)
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_summary = "Checks InternetExplorer Policy for Protected Mode over WMI.";


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96049");
  script_version("$Revision: 9365 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:34:21 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");  
  script_name("Checks InternetExplorer Policy for Protected Mode over WMI (Windows)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_mandatory_keys("Tools/Present/wmi");
   
#  script_require_ports(139, 445);
  script_dependencies("secpod_reg_enum.nasl", "GSHB_WMI_OSInfo.nasl");
  script_tag(name : "summary" , value : tag_summary);
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
  set_kb_item(name:"WMI/ProtModeIntraZone", value:"error");
  set_kb_item(name:"WMI/ProtModeTrustZone", value:"error");
  set_kb_item(name:"WMI/ProtModeInterZone", value:"error");
  set_kb_item(name:"WMI/ProtModeRestrZone", value:"error");
  set_kb_item(name:"WMI/ProtMode/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
  exit(0);
}

handle = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handle){
  set_kb_item(name:"WMI/ProtModeIntraZone", value:"error");
  set_kb_item(name:"WMI/ProtModeTrustZone", value:"error");
  set_kb_item(name:"WMI/ProtModeInterZone", value:"error");
  set_kb_item(name:"WMI/ProtModeRestrZone", value:"error");
  set_kb_item(name:"WMI/ProtMode/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  exit(0);
}

IntranetZone = wmi_reg_enum_value(wmi_handle:handle, key:"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1");
TrustedSiteZone = wmi_reg_enum_value(wmi_handle:handle, key:"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2");
InternetZone = wmi_reg_enum_value(wmi_handle:handle, key:"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3");
RestrictedSideZone = wmi_reg_enum_value(wmi_handle:handle, key:"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4");

if(OSVER  <  "6.0"){
  set_kb_item(name:"WMI/ProtModeIntraZone", value:"prevista");
  set_kb_item(name:"WMI/ProtModeTrustZone", value:"prevista");
  set_kb_item(name:"WMI/ProtModeInterZone", value:"prevista");
  set_kb_item(name:"WMI/ProtModeRestrZone", value:"prevista");
  wmi_close(wmi_handle:handle);
  exit(0);
}

if ("2500" >< IntranetZone){
  ProtModeIntraZone = wmi_reg_get_dword_val(wmi_handle:handle, key:"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1", val_name:"2500");
}else ProtModeIntraZone = "-1";

if ("2500" >< TrustedSiteZone){
  ProtModeTrustZone = wmi_reg_get_dword_val(wmi_handle:handle, key:"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2", val_name:"2500");
}else ProtModeTrustZone = "-1";

if ("2500" >< InternetZone){
  ProtModeInterZone = wmi_reg_get_dword_val(wmi_handle:handle, key:"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", val_name:"2500");
}else ProtModeInterZone = "-1";

if ("2500" >< RestrictedSideZone){
  ProtModeRestrZone = wmi_reg_get_dword_val(wmi_handle:handle, key:"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", val_name:"2500");
}else ProtModeRestrZone = "-1";

set_kb_item(name:"WMI/ProtModeIntraZone", value:ProtModeIntraZone);
set_kb_item(name:"WMI/ProtModeTrustZone", value:ProtModeTrustZone);
set_kb_item(name:"WMI/ProtModeInterZone", value:ProtModeInterZone);
set_kb_item(name:"WMI/ProtModeRestrZone", value:ProtModeRestrZone);

wmi_close(wmi_handle:handle);
exit(0);

