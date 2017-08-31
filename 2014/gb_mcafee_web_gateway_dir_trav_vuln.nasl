###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_web_gateway_dir_trav_vuln.nasl 6735 2017-07-17 09:56:49Z teissa $
#
# McAfee Web Gateway Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804420";
CPE = "cpe:/a:mcafee:web_gateway";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6735 $");
  script_cve_id("CVE-2014-2535");
  script_bugtraq_id(66193);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-17 11:56:49 +0200 (Mon, 17 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-04-08 13:16:45 +0530 (Tue, 08 Apr 2014)");
  script_name("McAfee Web Gateway Directory Traversal Vulnerability");

tag_summary =
"This host is running McAfee Web Gateway and is prone to directory traversal
vulnerability.";

tag_vuldetect =
"Get the installed version of McAfee Web Gateway with the help of detect NVT
and check the version is vulnerable or not.";

tag_insight =
"The flaw is due to an error within the MWG web filtering port when processing
requests.";

tag_impact =
"Successful exploitation will allow attackers to disclose potentially sensitive
information.

Impact Level: Application";

tag_affected =
"McAfee Web Gateway 7.4.x before 7.4.1, 7.3.x before 7.3.2.6, 7.2.0.9 and earlier";

tag_solution =
"Upgrade to McAfee Web Gateway 7.3.2.6 or 7.4.1 or later,
For updates refer to http://www.mcafee.com/us/products/web-gateway.aspx";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://secunia.com/advisories/56958");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/91772");
  script_xref(name : "URL" , value : "https://kc.mcafee.com/corporate/index?page=content&id=SB10063");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_mcafee_web_gateway_detect.nasl");
  script_mandatory_keys("McAfee/Web/Gateway/installed");
  script_require_ports("Services/www", 8080);
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variable initialization
mwgPort = "";
mwgVer = "";

## Get Application HTTP Port
if(!mwgPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get application version
mwgVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:mwgPort);
if(!mwgVer){
  exit(0);
}

if(version_is_less(version:mwgVer, test_version:"7.2.0.10"))
{
  security_message(port:mwgPort);
  exit(0);
}

if(mwgVer =~ "^7\.4")
{
  if(version_is_less(version:mwgVer, test_version:"7.4.1"))
  {
    security_message(port:mwgPort);
    exit(0);
  }
}

if(mwgVer =~ "^7\.3")
{
  if(version_is_less(version:mwgVer, test_version:"7.3.2.6"))
  {
    security_message(port:mwgPort);
    exit(0);
  }
}
