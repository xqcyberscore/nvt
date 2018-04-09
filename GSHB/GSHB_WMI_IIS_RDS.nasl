###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_WMI_IIS_RDS.nasl 9365 2018-04-06 07:34:21Z cfischer $
#
# Remote Data Service on InternetInformationServer (Windows)
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

tag_summary = "The script detects if Remote Data Service installed on InternetInformationServer.";


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96003");
  script_version("$Revision: 9365 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:34:21 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");  
  script_name("Remote Data Service on InternetInformationServer (Windows)");

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
  set_kb_item(name:"WMI/RDSServer/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
  set_kb_item(name:"WMI/RDSServer.DataFactory", value:"error");
  set_kb_item(name:"WMI/AdvancedDataFactory", value:"error");
  set_kb_item(name:"WMI/VbBusObj.VbBusObjCls", value:"error");
  exit(0);
}

handle = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handle){
  set_kb_item(name:"WMI/RDSServer/log", value:"wmi_connect: WMI Connect failed.");
  set_kb_item(name:"WMI/RDSServer.DataFactory", value:"error");
  set_kb_item(name:"WMI/AdvancedDataFactory", value:"error");
  set_kb_item(name:"WMI/VbBusObj.VbBusObjCls", value:"error");
  wmi_close(wmi_handle:handle);
  exit(0);
}

IISVer = wmi_reg_get_dword_val(wmi_handle:handle, key:"SOFTWARE\Microsoft\InetStp", val_name:"MajorVersion");

if (!IISVer){
  set_kb_item(name:"WMI/RDSServer/log", value:"IT-Grundschutz; No IIS installed!");
  set_kb_item(name:"WMI/RDSServer.DataFactory", value:"off");
  set_kb_item(name:"WMI/AdvancedDataFactory", value:"off");
  set_kb_item(name:"WMI/VbBusObj.VbBusObjCls", value:"off");
  log_message(port:0, proto: "IT-Grundschutz", data:"No IIS installed!");
  wmi_close(wmi_handle:handle);
  exit(0);
}

W2SVCPAR = wmi_reg_enum_key(wmi_handle:handle, key:"SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch");

if("RDSServer.DataFactory" >!< W2SVCPAR) set_kb_item(name:"WMI/RDSServer.DataFactory", value:"off");
else set_kb_item(name:"WMI/RDSServer.DataFactory", value:"on");

if("AdvancedDataFactory" >!< W2SVCPAR) set_kb_item(name:"WMI/AdvancedDataFactory", value:"off");
else set_kb_item(name:"WMI/AdvancedDataFactory", value:"on");

if("VbBusObj.VbBusObjCls" >!< W2SVCPAR) set_kb_item(name:"WMI/VbBusObj.VbBusObjCls", value:"off");
else set_kb_item(name:"WMI/VbBusObj.VbBusObjCls", value:"on");

wmi_close(wmi_handle:handle);

exit(0);
