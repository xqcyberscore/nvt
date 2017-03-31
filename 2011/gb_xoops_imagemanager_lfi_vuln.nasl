###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xoops_imagemanager_lfi_vuln.nasl 3978 2016-09-06 12:21:47Z cfi $
#
# Xoops 'imagemanager.php' Local File Inclusion Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_affected = "Xoops version 2.5.0 and prior.";

tag_insight = "The flaw is due to input validation error in 'target' parameter
to 'imagemanager.php', which allows attackers to read arbitrary files via a
../(dot dot) sequences.";

tag_solution = "Upgrade to version 2.5.1 or later,
For updates refer to http://sourceforge.net/projects/xoops";

tag_summary = "This host is running with Xoops and is prone to local file
inclusion vulnerability.";

if(description)
{
  script_id(801932);
  script_version("$Revision: 3978 $");
  script_tag(name:"last_modification", value:"$Date: 2016-09-06 14:21:47 +0200 (Tue, 06 Sep 2016) $");
  script_tag(name:"creation_date", value:"2011-05-16 15:25:30 +0200 (Mon, 16 May 2011)");
  script_bugtraq_id(47418);
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_name("Xoops 'imagemanager.php' Local File Inclusion Vulnerability");
  script_xref(name : "URL" , value : "http://dl.packetstormsecurity.net/1104-exploits/xoops250-lfi.txt");
  script_xref(name : "URL" , value : "http://www.allinfosec.com/2011/04/18/webapps-0day-xoops-2-5-0-imagemanager-php-lfi-vulnerability-2/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_summary("Check for local file inclusion vulnerability in OrangeHRM");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_dependencies("secpod_xoops_detect.nasl");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

##
## The script code starts here
##

include("http_func.inc");
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

## Get XOOPS version from KB
xpVer = get_kb_item("www/"+ port + "/XOOPS");
if(!xpVer){
  exit(0);
}

xpVer = eregmatch(pattern:"([0-9.]+)", string:xpVer);
if(xpVer[1] != NULL)
{
  ## Check for the XOOPS version less or equal 2.5.0
  if(version_is_less_equal(version:xpVer[1], test_version:"2.5.0")){
    security_message(port);
  }
}
