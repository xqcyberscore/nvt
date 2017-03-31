###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_youtube_gallery_sql_inj_vuln.nasl 3522 2016-06-15 12:39:54Z benallard $
#
# Joomla! YouTube Gallery Component 'gallery.php' SQL Injection Vulnerability
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804720");
  script_version("$Revision: 3522 $");
  script_cve_id("CVE-2014-4960");
  script_bugtraq_id(68676);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-06-15 14:39:54 +0200 (Wed, 15 Jun 2016) $");
  script_tag(name:"creation_date", value:"2014-07-24 16:09:39 +0530 (Thu, 24 Jul 2014)");
  script_name("Joomla! YouTube Gallery Component 'gallery.php' SQL Injection Vulnerability");

  tag_summary =
"This host is installed with Joomla! YouTube Gallery Component and is prone
to sql injection vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the
version is vulnerable or not.";

  tag_insight =
"Flaw is due to the /com_youtubegallery/models/gallery.php script not properly
sanitizing user-supplied input to the 'listid' and 'themeid' parameters.";

  tag_impact =
"Successful exploitation will allow remote attackers to execute arbitrary SQL
statements on the vulnerable system, which may leads to access or modify data
in the underlying database.

Impact Level: Application";

  tag_affected =
"Joomla! YouTube Gallery Component version 4.1.7, Prior versions may also be
affected.";

  tag_solution =
"Upgrade to version 4.1.9 or higher,
For updates refer to http://www.joomlaboat.com/youtube-gallery";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/34087");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/127497");
  script_summary("Check if Joomla Youtube Gallery is vulnerable to sql injection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
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

## Get Joomla Location
if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

## Construct the attack request
url = dir + "/index.php?option=com_youtubegallery&view=youtubegallery"
          + "&listid=1'SQLInjectionTest&themeid=1";

## Try attack and check the response to confirm vulnerability
if(http_vuln_check(port:http_port, url:url, check_header:FALSE,
   pattern:"You have an error in your SQL syntax.*SQLInjectionTest"))
{
  security_message(http_port);
  exit(0);
}
