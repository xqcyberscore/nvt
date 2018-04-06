###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_winftp_server_dos_vuln.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# WinFTP Server PASV Command Denial of Service Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2008 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will let the user crash the application to cause
  denial of service.";
tag_affected = "Win FTP Server version 2.3.0 or prior.";
tag_insight = "The flaw is due to an error when handling the PASV and NLST commands. These can
  be exploited through sending multiple login request ending with PASV command.";
tag_solution = "Solution/Patch not available as on 19th December 2008. For updates
  refer, http://www.wftpserver.com/wftpserver.htm";
tag_summary = "This host is running WinFTP Server and is prone to Denial of
  Service Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900450");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-12-26 14:23:17 +0100 (Fri, 26 Dec 2008)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_bugtraq_id(31686);
  script_cve_id("CVE-2008-5666");	
  script_name("WinFTP Server PASV Command Denial of Service Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32209");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/6717");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "secpod_reg_enum.nasl");
  script_require_ports("Services/ftp", 21, 139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smb_nt.inc");
include("ftp_func.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

port = get_kb_item("Services/ftp");
if(!port){
  port = 21;
}

if(!get_port_state(port)){
  exit(0);
}

banner = get_ftp_banner(port:port);
if("Welcome to WinFtp Server" >!< banner){
  exit(0);
}

regKey = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                             "\Uninstall\WinFtp Server_is1", item:"DisplayName");
if("WinFtp Server" >< regKey)
{
  winftpVer = eregmatch(pattern:"WinFtp Server ([0-9.]+)", string:regKey);

  # Grep for version 2.3.0 and prior.
  if(version_is_less_equal(version:winftpVer[1], test_version:"2.3.0")){
    security_message(port);
  }
}
