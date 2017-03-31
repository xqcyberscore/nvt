##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_pivotx_data_manipulation_vuln.nasl 3114 2016-04-19 10:07:15Z benallard $
#
# PivotX 'Reset my password' Feature Data Manipulation Vulnerability
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
################################i###############################################

tag_impact = "Successful exploitation will allow remote attackers to gain privileges via
  unknown vectors.
  Impact Level: Application.";
tag_affected = "PivotX version before 2.2.5";
tag_insight = "This issue is caused by an error in the 'Reset my password' feature, which
  could allow unauthenticated attackers to change the password of any account
  by guessing the username.";
tag_solution = "Upgrade to PivotX version 2.2.5 or later
  For updates refer to http://pivotx.net/";
tag_summary = "This host is running PivotX and is prone to data manipulation
  vulnerability.";

if(description)
{
  script_id(902343);
  script_version("$Revision: 3114 $");
  script_tag(name:"last_modification", value:"$Date: 2016-04-19 12:07:15 +0200 (Tue, 19 Apr 2016) $");
  script_tag(name:"creation_date", value:"2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)");
  script_cve_id("CVE-2011-1035");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PivotX 'Reset my password' Feature Data Manipulation Vulnerability");
  script_xref(name : "URL" , value : "http://forum.pivotx.net/viewtopic.php?f=2&t=1967");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0445");
  script_xref(name : "URL" , value : "http://forum.pivotx.net/viewtopic.php?p=10639#p10639");
  script_xref(name : "URL" , value : "http://blog.pivotx.net/2011-02-16/pivotx-225-released");
  
  script_tag(name:"qod_type", value:"remote_banner");
  script_summary("Check for the version of PivotX");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_pivotx_detect.nasl");
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

## Get HTTP Port
pxPort = get_http_port(default:80);
if(!pxPort){
  exit(0);
}

pxVer = get_version_from_kb(port:pxPort, app:"PivotX");
if(pxVer)
{
  ## Check for the version less than 2.2.5
  if(version_is_less(version:pxVer, test_version:"2.2.5"))
  {
    security_message(pxPort);
    exit(0);
  }
}  
