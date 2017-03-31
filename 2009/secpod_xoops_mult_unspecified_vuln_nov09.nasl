###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xoops_mult_unspecified_vuln_nov09.nasl 5148 2017-01-31 13:16:55Z teissa $
#
# XOOPS Multiple Unspecified Vulnerabilities - Nov09
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Unknow impact
  Impact Level: Application";
tag_affected = "XOOPS version prior to 2.4.0 Final on all running platform.";
tag_insight = "The flaws are caused by unspecified errors with unknown impacts and unknown
  attack vectors.";
tag_solution = "Upgrade to XOOPS version 2.4.0 Final or later.
  http://www.xoops.org/modules/core/";
tag_summary = "This host is running XOOPS and is prone to multiple unspecified
  vulnerabilities.";

if(description)
{
  script_id(900893);
  script_version("$Revision: 5148 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-31 14:16:55 +0100 (Tue, 31 Jan 2017) $");
  script_tag(name:"creation_date", value:"2009-11-20 06:52:52 +0100 (Fri, 20 Nov 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3963");
  script_bugtraq_id(36955);
  script_name("XOOPS Multiple Unspecified Vulnerabilities - Nov09");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/54181");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3174");
  script_xref(name : "URL" , value : "http://www.xoops.org/modules/news/article.php?storyid=5064");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_xoops_detect.nasl");
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

xoopsPort = get_http_port(default:80);
if(!xoopsPort){
  exit(0);
}

xoopsVer = get_kb_item("www/"+ xoopsPort + "/XOOPS");
if(!xoopsVer){
  exit(0);
}

xoopsVer = eregmatch(pattern:"^(.+) under (/.*)$", string:xoopsVer);
if(xoopsVer[1])
{
  # Check for XOOPS version prior to 2.4.0 (2.4.0 Final)
  if(version_is_less(version:xoopsVer[1], test_version:"2.4.0")){
    security_message(xoopsPort);
  }
}
