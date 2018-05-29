##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_aastra_ip_telephone_telnet_sec_bypass_vuln.nasl 9984 2018-05-28 14:36:22Z cfischer $
#
# Aastra IP Telephone Hardcoded Telnet Password Security Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803190");
  script_version("$Revision: 9984 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-05-28 16:36:22 +0200 (Mon, 28 May 2018) $");
  script_tag(name:"creation_date", value:"2013-04-09 15:08:24 +0530 (Tue, 09 Apr 2013)");
  script_name("Aastra IP Telephone Hardcoded Telnet Password Security Bypass Vulnerability");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Apr/42");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/526207");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/aastra-ip-telephone-hardcoded-password");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_require_ports("Services/www", 80, "Services/telnet", 23);
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Aastra_6753i/banner");

  script_tag(name:"insight", value:"Aastra 6753i IP Phone installs with default hard coded
  administrator credentials (username/password combination).");
  script_tag(name:"solution", value:"Upgrade to latest version of Aastra 6753i IP Telephone. For
  details refer http://www.aastra.in/aastra-6753i.htm");
  script_tag(name:"summary", value:"This host is running Aastra IP Telephone and is prone to
  security bypass vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to access the device
  and gain privileged access.

  Impact Level: Application");
  script_tag(name:"affected", value:"Aastra 6753i IP Telephone");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("telnet_func.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if('Basic realm="Aastra 6753i"' >!< banner){
  exit(0);
}

tport = get_telnet_port(default:23);
tbanner = get_telnet_banner(port:tport);
if("VxWorks login:" >!< tbanner){
  exit(0);
}

soc = open_sock_tcp(tport);
if(!soc){
  exit(0);
}

send(socket:soc, data:string("admin","\r\n"));
resp = recv(socket:soc, length:4096);

if("Password:" >< resp)
{
  send(socket:soc, data:string("[M]qozn~","\r\n"));
  resp = recv(socket:soc, length:4096);
  if("->" >< resp && "Login incorrect" >!< resp)
  {
    security_message(port:tport);
    close(soc);
    exit(0);
  }
}
close(soc);

exit(99);
