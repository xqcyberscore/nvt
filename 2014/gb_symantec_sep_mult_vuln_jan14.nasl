###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_sep_mult_vuln_jan14.nasl 7174 2017-09-18 11:48:08Z asteins $
#
# Symantec Endpoint Protection Multiple Vulnerabilities Jan-14
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:symantec:endpoint_protection";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804199";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 7174 $");
  script_cve_id("CVE-2013-5009", "CVE-2013-5010", "CVE-2013-5011");
  script_bugtraq_id(64128, 64129, 64130);
  script_tag(name:"cvss_base", value:"7.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 13:48:08 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2014-01-27 16:29:04 +0530 (Mon, 27 Jan 2014)");
  script_name("Symantec Endpoint Protection Multiple Vulnerabilities Jan-14");

  tag_summary =
"This host is installed with Symantec Endpoint Protection is prone to
multiple vulnerabilities.";

  tag_vuldetect =
"Get the installed version of Symantec Endpoint Protection and check the
version is vulnerable or not.";

  tag_insight =
"The flaw exists due to,
 - application not properly verifying the authentication of authorised users.
 - an unspecified error in Application/Device Control (ADC) component.
 - an unquoted search path.";

  tag_impact =
"Successful exploitation may allow an attacker to gain escalated privileges
and access sensitive files or directories.

Impact Level: System/Application.";

  tag_affected =
"Symantec Endpoint Protection (SEP) 11.x before version 11.0.7.4 and 12.x
before 12.1.2 RU2 and Endpoint Protection Small Business Edition 12.x before
12.1.2 RU2";

  tag_solution =
"Upgrade to Symantec Endpoint Protection (SEP) version 11.0.7.4 or 12.1.2 RU2
or Endpoint Protection Small Business Edition 12.x before version 12.1.2RU2.
For Updates refer http://www.symantec.com/en/in/endpoint-protection.

*****
NOTE: Ignore this warning if above mentioned patch is installed.
*****";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://secunia.com/advisories/56354/");
  script_xref(name : "URL" , value : "http://www.symantec.com/connect/articles/what-are-symantec-endpoint-protection-sep-versions-released-officialy");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_mandatory_keys("Symantec/Endpoint/Protection");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");
include("global_settings.inc");

## Variable Initialization
sepVer= "";

## Get version
if(!sepVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
    exit(0);
}

## Check for Symantec Endpoint Protection versions
## Get SEP Product type from KB
sepType = get_kb_item("Symantec/SEP/SmallBusiness");

## Check for Symantec Endpoint Protection versions
##  Check for vulnerable version 11.0.7.4 = 11.0.7400.1398
if(isnull(sepType) &&
   version_in_range(version:sepVer, test_version:"11.0", test_version2:"11.0.7400.1397")||
   version_in_range(version:sepVer, test_version:"12.1", test_version2:"12.1.2015.2014"))
{
   security_message(0);
   exit(0);
}

## Check for Symantec Endpoint Protection Small Business Edition (SEPSBE) 12.x before  RU2 (12.1.2015.2015)
## Check if product type is SEPSB
if("sepsb" >< sepType  && sepVer =~ "^12" &&
   version_is_less(version:sepVer, test_version:"12.1.2015.2015"))
{
   security_message(0);
   exit(0);
}
