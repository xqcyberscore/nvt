###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_WMI_BootDrive.nasl 9365 2018-04-06 07:34:21Z cfischer $
#
# WMI Drives Test
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

tag_summary = "Tests WMI Drives Status.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96012");
  script_version("$Revision: 9365 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:34:21 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");  
  script_name("WMI Drives Status (win)");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_mandatory_keys("Tools/Present/wmi");
   
#  script_require_ports(139, 445);
  script_dependencies("secpod_reg_enum.nasl", "GSHB_WMI_OSInfo.nasl");
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("wmi_file.inc");

host    = get_host_ip();
usrname = get_kb_item("SMB/login");
domain  = get_kb_item("SMB/domain");
if (domain){
  usrname = domain + '\\' + usrname;
}
passwd  = get_kb_item("SMB/password");
OSVER = get_kb_item("WMI/WMI_OSVER");
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");

if(!OSVER || OSVER >< "none"){
  set_kb_item(name:"WMI/FS", value:"error");
  set_kb_item(name:"WMI/FDD", value:"error");
  set_kb_item(name:"WMI/CD", value:"error");
  set_kb_item(name:"WMI/USB", value:"error");
  set_kb_item(name:"WMI/BOOTINI", value:"error");
  set_kb_item(name:"WMI/BOOTDRIVE/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
  exit(0);
}

handle = wmi_connect(host:host, username:usrname, password:passwd);

if(!handle){
  set_kb_item(name:"WMI/FS", value:"error");
  set_kb_item(name:"WMI/FDD", value:"error");
  set_kb_item(name:"WMI/CD", value:"error");
  set_kb_item(name:"WMI/USB", value:"error");
  set_kb_item(name:"WMI/BOOTINI", value:"error");
  set_kb_item(name:"WMI/BOOTDRIVE/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  exit(0);
}

query1 = 'select DeviceID from WIN32_FloppyDrive';
query2 = 'select DeviceID from WIN32_CDROMDrive';
query3 = 'select DeviceID from WIN32_USBController';
query4 = 'select FileSystem from WIN32_LogicalDisk WHERE DriveType = 3';

WMIFDD = wmi_query(wmi_handle:handle, query:query1);
WMICD = wmi_query(wmi_handle:handle, query:query2);
WMIUSB = wmi_query(wmi_handle:handle, query:query3);
WMIFS = wmi_query(wmi_handle:handle, query:query4);
if (OSVER < 6){
    BOOTINI = wmi_file_is_file_writeable(handle:handle, filePath:"c:\\boot.ini");
}else BOOTINI = "No boot.ini";


if(!WMIFDD) WMIFDD = "None";
if(!WMICD) WMICD = "None";
if(!WMIUSB) WMIUSB = "None";
if(!WMIFS) WMIFS = "None";
if(!BOOTINI) BOOTINI = "None";

set_kb_item(name:"WMI/FS", value:WMIFS);
set_kb_item(name:"WMI/FDD", value:WMIFDD);
set_kb_item(name:"WMI/CD", value:WMICD);
set_kb_item(name:"WMI/USB", value:WMIUSB);
set_kb_item(name:"WMI/BOOTINI", value:BOOTINI);

wmi_close(wmi_handle:handle);

exit(0);

