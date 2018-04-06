###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moziloCMS_mult_xss_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# moziloCMS Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi<santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow remote attackers to execute
arbitrary HTML and script code in a user's browser session in the context of
an affected site.

Impact Level: Application.";

tag_affected = "moziloCMS version 1.11.1 and prior on all running platform.";

tag_insight = "The flaws are due to an error in 'admin/index.php'. The input
values are not properly verified before being used via 'cat' and file parameters
in an 'editsite' action.";

tag_solution = "Upgrade to version 1.12 or later,
For updates refer to http://cms.mozilo.de/index.php?cat=10_moziloCMS&page=50_Download";

tag_summary = "The host is running moziloCMS and is prone to Multiple Cross Site
Scripting Vulnerabilities";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801076");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-12-09 07:52:52 +0100 (Wed, 09 Dec 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-4209");
  script_bugtraq_id(35212);
  script_name("moziloCMS Multiple Cross Site Scripting Vulnerabilities");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/388498.php");
  script_xref(name : "URL" , value : "http://downloads.securityfocus.com/vulnerabilities/exploits/35212.txt");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("mozilloCMS_detect.nasl");
  script_family("Web application abuses");
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

port = get_http_port(default:80);
if(!port){
  exit(0);
}

mzVer = get_kb_item("www/" + port + "/moziloCMS");
if(!mzVer){
  exit(0);
}

mzVer = eregmatch(pattern:"^(.+) under (/.*)$", string:mzVer);
if(mzVer[1] != NULL)
{
  if(version_is_less_equal(version:mzVer[1], test_version:"1.11.1")){
    security_message(port:port);
  }
}

