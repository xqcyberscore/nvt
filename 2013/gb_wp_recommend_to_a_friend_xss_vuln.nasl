###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wp_recommend_to_a_friend_xss_vuln.nasl 34057 2013-12-30 18:18:36Z dec$
#
# Wordpress Recommend to a friend plugin Cross Site Scripting Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804048";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6093 $");
  script_cve_id("CVE-2013-7276");
  script_bugtraq_id(64548);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-05-10 11:03:18 +0200 (Wed, 10 May 2017) $");
  script_tag(name:"creation_date", value:"2013-12-30 18:18:36 +0530 (Mon, 30 Dec 2013)");
  script_name("Wordpress Recommend to a friend plugin Cross Site Scripting Vulnerability");

  tag_summary =
"This host is installed with Wordpress Recommend to a friend plugin and is
prone to cross site scripting vulnerability.";

  tag_vuldetect =
"Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not.";

  tag_insight =
"Flaw is due to an improper validation of user supplied input to the
'current_url' parameter in 'raf_form.php' script.";

  tag_impact =
"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site.

Impact Level: Application";

  tag_affected =
"WordPress Recommend to a friend Plugin version 2.0.2, Other versions may
also be affected.";

  tag_solution =
"No Solution or patch is available as of 30th December, 2013. Information
regarding this issue will be updated once the solution details are available.
For updates refer to http://wordpress.org/plugins/recommend-a-friend";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"solution_type", value:"NoneAvailable");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/56209");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/56209");
  script_xref(name : "URL" , value : "http://cxsecurity.com/issue/WLB-2013120161");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/wordpress-recommend-cross-site-scripting");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
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
if(!http_port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get WordPress Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:http_port)){
  exit(0);
}

## Construct the attack request
url = dir + '/wp-content/plugins/recommend-a-friend/inc/raf_form.php'+
            '?current_url="/><script>alert(document.cookie);</script>';

## Check Exploit is working
if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
                   pattern:"<script>alert\(document.cookie\);</script>",
                   extra_check:">Recommend this page"))
{
  security_message(http_port);
  exit(0);
}
