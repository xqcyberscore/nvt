###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_photoshop_mult_bof_vuln.nasl 8356 2018-01-10 08:00:39Z teissa $
#
# Adobe Photoshop Multiple Buffer Overflow Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code within the context of the affected application or cause denial of
  service.
  Impact Level: Application/System";
tag_affected = "Adobe Photoshop CS4 before 11.0.2";
tag_insight = "This flaw is caused by improper bounds checking on user-supplied data,
  which could allow a remote attacker to execute arbitrary code on the system
  by persuading a victim to open a specially-crafted 'ASL', '.ABR', or '.GRD'
  file.";
tag_solution = "Upgrade to Adobe Photoshop CS4 11.0.2 or later,
  For updates refer to http://www.adobe.com/downloads/";
tag_summary = "This host is installed with Adobe Photoshop and is prone to Buffer
  Overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801221");
  script_version("$Revision: 8356 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-10 09:00:39 +0100 (Wed, 10 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-06-15 06:05:27 +0200 (Tue, 15 Jun 2010)");
  script_bugtraq_id(40389);
  script_cve_id("CVE-2010-1296");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Photoshop Multiple Buffer Overflow Vulnerabilities");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/58888");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb10-13.html");
  script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4940.php");
  script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4939.php");
  script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4938.php");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_adobe_photoshop_detect.nasl");
  script_require_keys("Adobe/Photoshop/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

## Variable Initiliazation
adobeVer = "";

## Get version from KB
## Check for adobe versions CS4
adobeVer = get_kb_item("Adobe/Photoshop/Ver");
if(!adobeVer || "CS4" >!< adobeVer){
  exit(0);
}

adobeVer = eregmatch(pattern:"CS([0-9.]+) ?([0-9.]+)", string: adobeVer);

if(!isnull(adobeVer[2]))
{
  ##Grep for Adobe Photoshop CS4 before 11.0.2
  if(version_is_less(version:adobeVer[2], test_version:"11.0.2") ){
    security_message(0);
  }
}
