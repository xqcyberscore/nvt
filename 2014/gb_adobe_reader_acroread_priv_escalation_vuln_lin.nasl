###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_acroread_priv_escalation_vuln_lin.nasl 6692 2017-07-12 09:57:43Z teissa $
#
# Adobe Reader 'acroread' Privilege Escalation Vulnerability (Linux)
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

CPE = "cpe:/a:adobe:acrobat_reader";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804371";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6692 $");
  script_cve_id("CVE-2008-0883");
  script_bugtraq_id(28091);
  script_tag(name:"cvss_base", value:"3.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:57:43 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-04-08 18:15:57 +0530 (Tue, 08 Apr 2014)");
  script_name("Adobe Reader 'acroread' Privilege Escalation Vulnerability (Linux)");

  tag_summary =
"This host is installed with Adobe Reader and is prone to privilege escalation
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaw is due to the insecure handling of temporary files within the 'acroread'
script.";

  tag_impact =
"Successful exploitation will allow attackers to gain escalated privileges on
the system.

Impact Level: System/Application";

  tag_affected =
"Adobe Reader version 8.1.2 on Linux.";

  tag_solution =
"Apply Security Update mentioned in the advisory from the below link,
http://www.adobe.com/support/downloads/detail.jsp?ftpID=3992";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/29229");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/40987");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id?1019539");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/advisories/apsa08-02.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_mandatory_keys("Adobe/Reader/Linux/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
readerVer = "";

## Get version
if(!readerVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

if(readerVer && readerVer =~ "^8")
{
  ## Check Adobe Reader vulnerable versions
  if(version_is_equal(version:readerVer, test_version:"8.1.2"))
   {
    security_message(0);
    exit(0);
  }
}
