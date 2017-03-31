###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_domino_inotes_xss_vuln.nasl 3557 2016-06-20 08:07:14Z benallard $
#
# IBM Lotus Domino iNotes Cross Site Scripting Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803975";
CPE = "cpe:/a:ibm:lotus_domino";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 3557 $");
  script_cve_id("CVE-2013-5389", "CVE-2013-5388");
  script_bugtraq_id(63265,63266);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"$Date: 2016-06-20 10:07:14 +0200 (Mon, 20 Jun 2016) $");
  script_tag(name:"creation_date", value:"2013-12-09 15:25:56 +0530 (Mon, 09 Dec 2013)");
  script_name("IBM Lotus Domino iNotes Cross Site Scripting Vulnerability");

  tag_summary =
"The host is installed with IBM Lotus Domino and is prone to cross site
scripting vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

 tag_insight =
"The flaw is in the iNotes. No much information is publicly available about
this issue.";

  tag_impact =
"Successful exploitation will allow remote attackers to inject arbitrary
web script.

Impact Level: Application";

  tag_affected =
"IBM Lotus Domino 8.5.3 before FP5 IF2 and 9.0 before IF5.";

  tag_solution =
"Upgrade to IBM Lotus Domino version 8.5.3 FP5 IF2 or 9.0 IF5 or later.
For more information refer to,
http://www-01.ibm.com/support/docview.wss?uid=swg21653149";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/87123");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/87125");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21653149");
  script_summary("Determine if IBM Lotus Domino version is vulnerable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_lotus_domino_detect.nasl");
  script_mandatory_keys("Domino/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");
include("global_settings.inc");

## Variable Initialization
domVer = "";
domPort = "";

# get the port
if(!domPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

# get the version
if(!domVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:domPort)){
  exit(0);
}

domVer = ereg_replace(pattern:"FP", string:domVer, replace: ".");

if(version_is_less(version:domVer, test_version:"8.5.3.5") ||
   version_is_equal(version:domVer, test_version:"9.0.0.0"))
{
  security_message(0);
  exit(0);
}
