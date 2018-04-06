###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_servu_ftp_server_mult_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Rhinosoft Serv-U FTP Multiple Vulnerabilities
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will let the attacker conduct directory traversal
  attack or can cause denial of service.
  Impact Level: System/Application";
tag_affected = "Rhinosoft Serv-U FTP Server version 7.4.0.1 or prior.";
tag_insight = "- Error when processing 'MKD' commands which can be exploited to create
    directories residing outside a given user's home directory via directory
    traversal attacks.
  - Error when handing certain FTP commands, by sending a large number of
    'SMNT' commands without an argument causes the application to stop
    responding.";
tag_solution = "Upgrade to Rhinosoft Serv-U FTP Server version 10 or later,
  For updates refer to http://www.serv-u.com";
tag_summary = "This host is running Serv-U FTP Server and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900483");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-03-26 11:23:52 +0100 (Thu, 26 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_cve_id("CVE-2009-0967", "CVE-2009-1031");
  script_bugtraq_id(34127, 34125);
  script_name("Rhinosoft Serv-U FTP Multiple Vulnerabilities");


  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_servu_ftp_server_detect.nasl");
  script_require_keys("Serv-U/FTPServ/Ver");
  script_require_ports("Services/ftp", 21);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8211");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8212");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/49260");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/0738");
  exit(0);
}


include("ftp_func.inc");
include("version_func.inc");

ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  exit(0);
}

banner = get_ftp_banner(port:ftpPort);
if("Serv-U FTP Server" >!< banner){
  exit(0);
}

servuVer = get_kb_item("Serv-U/FTPServ/Ver");
if(!servuVer){
  exit(0);
}

# Check for version 7.4.0.1 and prior
if(version_is_less_equal(version:servuVer, test_version:"7.4.0.1")){
  security_message(ftpPort);
}
