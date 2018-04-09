###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_WMI_get_Shares.nasl 9365 2018-04-06 07:34:21Z cfischer $
#
# Get all Windows Shares over WMI (win)
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

tag_summary = "Get all Windows Shares over WMI.

  and check the Networkaccess for Anonymous (IPC$ NullSession)";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96026");
  script_version("$Revision: 9365 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:34:21 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("Get all Windows Shares over WMI (win)");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB");
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
    set_kb_item(name:"WMI/Shares", value:"error");
    set_kb_item(name:"WMI/IPC", value:"error");
    log_message(port:0, proto: "IT-Grundschutz", data:string("No access to SMB host. Firewall is activated or there is not a Windows system."));
    exit(0);
}

handle = wmi_connect(host:host, username:usrname, password:passwd);
handlereg = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handle){
    security_message("wmi_connect: WMI Connect failed.");
    set_kb_item(name:"WMI/Shares", value:"error");
    set_kb_item(name:"WMI/IPC", value:"error");
    wmi_close(wmi_handle:handle);
    wmi_close(wmi_handle:handlereg);
    exit(0);
}

query = 'select Name from Win32_Share';
SHARES = wmi_query(wmi_handle:handle, query:query);



IPC = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Control\LSA", val_name:"RestrictAnonymous");

AUTOSHARE = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", val_name:"AutoShareServer");



if(!SHARES) SHARES = "None";
if(!IPC) IPC = "None";
if(!AUTOSHARE) AUTOSHARE = "None";

set_kb_item(name:"WMI/Shares", value:SHARES);
set_kb_item(name:"WMI/IPC", value:IPC);
set_kb_item(name:"WMI/AUTOSHARE", value:AUTOSHARE);

wmi_close(wmi_handle:handle);
wmi_close(wmi_handle:handlereg);


exit(0);
