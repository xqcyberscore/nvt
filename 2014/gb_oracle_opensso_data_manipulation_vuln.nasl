###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_opensso_data_manipulation_vuln.nasl 6637 2017-07-10 09:58:13Z teissa $
#
# Oracle OpenSSO Administration Component Data Manipulation Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804437";
CPE = "cpe:/a:oracle:opensso";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6637 $");
  script_cve_id("CVE-2012-0079");
  script_bugtraq_id(51492);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 11:58:13 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-04-22 14:57:24 +0530 (Tue, 22 Apr 2014)");
  script_name("Oracle OpenSSO Administration Component Data Manipulation Vulnerability");

  tag_summary =
"This host is running Oracle OpenSSO and is prone to data manipulation
vulnerability.";

  tag_vuldetect =
"Get the installed version of Oracle OpenSSO with the help of detect NVT
and check the version is vulnerable or not.";

  tag_insight =
"The flaw is due to an unspecified error in the Administration component.";

  tag_impact =
"Successful exploitation will allow attackers to update, insert, or delete
certain Oracle OpenSSO accessible data.

Impact Level: Application";

  tag_affected =
"Oracle OpenSSO version 7.1 and 8.0";

  tag_solution =
"Apply the patch from below link,
http://www.oracle.com/technetwork/topics/security/cpujan2012-366304.html

*****
NOTE: Ignore this warning, if above mentioned patch is manually applied.
*****";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "");
  script_xref(name : "URL" , value : "");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("secpod_sun_opensso_detect.nasl");
  script_mandatory_keys("Oracle/OpenSSO/installed");
  script_require_ports("Services/www", 8080);
  exit(0);
}


include("version_func.inc");
include("host_details.inc");
include("global_settings.inc");

## Variable initialization
ooPort = "";
ooVer = "";

## Get Application HTTP Port
if(!ooPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get application version
ooVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:ooPort);
if(!ooVer){
  exit(0);
}

if(version_is_equal(version:ooVer, test_version:"8.0") ||
   version_is_equal(version:ooVer, test_version:"7.1"))
{
  security_message(port:ooPort);
  exit(0);
}
