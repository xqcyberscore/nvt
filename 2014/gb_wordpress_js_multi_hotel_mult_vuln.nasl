###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_js_multi_hotel_mult_vuln.nasl 6759 2017-07-19 09:56:33Z teissa $
#
# WordPress Js-Multi-Hotel Plugin Multiple Vulnerabilities
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804572";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6759 $");
  script_bugtraq_id(66529);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-19 11:56:33 +0200 (Wed, 19 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-05-08 11:09:59 +0530 (Thu, 08 May 2014)");
  script_name("WordPress Js-Multi-Hotel Plugin Multiple Vulnerabilities");

  tag_summary =
"This host is installed with Wordpress Js-Multi-Hotel plugin and is prone to
multiple vulnerabilities.";

  tag_vuldetect =
"Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not.";

  tag_insight =
"Multiple flaws are due to,
- Input passed via the 'file' parameter show_image.php and 'path' parameter
  to delete_img.php are not properly sanitized before being returned to the user.
- The /functions.php, /myCalendar.php, /refreshDate.php, /show_image.php,
  /widget.php, /phpthumb/GdThumb.inc.php, /phpthumb/thumb_plugins/gd_reflection.inc.php,
  and /includes/timthumb.php scripts discloses the software's installation path.";

  tag_impact =
"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site,
and cause a denial of service via CPU consumption.

Impact Level: System/Application";

  tag_affected =
"WordPress JS MultiHotel Plugin version 2.2.1, Other versions may also be
affected.";

  tag_solution =
"No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name : "URL" , value : "http://websecurity.com.ua/7082");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/125959");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2014/Mar/413");
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
url = dir + '/wp-content/plugins/js-multihotel/includes/delete_img.php'
          + '?path=<body onload=with(document)alert(cookie)>';

## Confirm the Exploit
## Extra Check is not possible
if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
   pattern:"<body onload=with\(document\)alert\(cookie\)>"))
{
  security_message(http_port);
  exit(0);
}
