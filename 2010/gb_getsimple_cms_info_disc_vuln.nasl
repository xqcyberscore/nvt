##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_getsimple_cms_info_disc_vuln.nasl 5306 2017-02-16 09:00:16Z teissa $
#
# GetSimple CMS Administrative Credentials Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow remote attackers to obtain sensitive
  information.
  Impact Level: Application.";
tag_affected = "GetSimple CMS 2.01 and 2.02";

tag_insight = "GetSimple does not use a SQL Database. Instead it uses a '.xml' files located
  at  '/GetSimple/data'. The administrators username and password hash can be
  obtained by navigating to the '/data/other/user.xml' xml file.";
tag_solution = "Apply the patch or upagrade to GetSimple CMS 2.03 or later,
  For updates refer to http://get-simple.info/download/";
tag_summary = "This host is running GetSimple CMS and is prone to administrative
  credentials disclosure vulnerability.";

if(description)
{
  script_id(801551);
  script_version("$Revision: 5306 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-16 10:00:16 +0100 (Thu, 16 Feb 2017) $");
  script_tag(name:"creation_date", value:"2010-11-30 12:42:12 +0100 (Tue, 30 Nov 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("GetSimple CMS Administrative Credentials Disclosure Vulnerability");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15605/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_getsimple_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

gscmsPort = get_http_port(default:80);
if(!gscmsPort){
  exit(0);
}

if(!dir = get_dir_from_kb(port:gscmsPort, app:"GetSimple_cms")){
  exit(0);
}

## Try attack and check the response to confirm vulnerability.
if(http_vuln_check(port:gscmsPort, url:dir + "/data/other/user.xml",
                   pattern:"(<PWD>.*</PWD>)")){
  security_message(port:gscmsPort);
}
