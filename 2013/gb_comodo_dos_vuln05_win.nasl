###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_comodo_dos_vuln05_win.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Comodo Internet Security Denial of Service Vulnerability-05
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation allow attackers to cause denial of service condition.
  Impact Level: Application";

tag_summary = "The host is installed with Comodo Internet Security and is prone
  to denial of service vulnerability.";
tag_solution = "Upgrade to Comodo Internet Security version 5.4.189822.1355 or later,
  For updates refer to http://personalfirewall.comodo.com";
tag_insight = "Flaw related to the antivirus component, triggered when a user opens an
  unspecified malformed PST file.";
tag_affected = "Comodo Internet Security versions before 5.4.189822.1355";

if(description)
{
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_oid("1.3.6.1.4.1.25623.1.0.803692");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2011-5120");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-07-05 16:28:19 +0530 (Fri, 05 Jul 2013)");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Comodo Internet Security Denial of Service Vulnerability-05");

  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/429024.php");
  script_xref(name : "URL" , value : "http://personalfirewall.comodo.com/release_notes.html");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_comodo_internet_security_detect_win.nasl");
  script_mandatory_keys("Comodo/InternetSecurity/Win/Ver");
  exit(0);
}


include("version_func.inc");

# Variable Initialization
Ver ="";

# Get the version from KB
Ver = get_kb_item("Comodo/InternetSecurity/Win/Ver");

# Check for Comodo Internet Security Version
if(Ver)
{
  if(version_is_less(version:Ver, test_version:"5.4.189822.1355")){
    security_message(0);
    exit(0);
  }
}
