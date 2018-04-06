###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_oracle_virtualbox_unspecified_vuln_win.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Oracle VM VirtualBox Unspecified Vulnerability (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
###############################################################################

tag_solution = "Apply the patch from below link,
  http://www.oracle.com/technetwork/topics/security/cpujuly2011-313328.html

  *****
  NOTE: Ignore this warning, if above mentioned workaround is manually applied.
  *****";

tag_impact = "Successful exploitation allows local users to affect confidentiality,
  integrity and availability via unknown vectors.
  Impact Level: Application";
tag_affected = "Oracle VM VirtualBox version 4.0";
tag_insight = "The flaw is due to unspecified error related to 'Guest Additions for
  Windows' sub component.";
tag_summary = "This host is installed with Oracle VM VirtualBox and is prone to
  unspecified vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902549");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-07-29 17:55:33 +0200 (Fri, 29 Jul 2011)");
  script_cve_id("CVE-2011-2300");
  script_bugtraq_id(48793);
  script_tag(name:"cvss_base", value:"3.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_name("Oracle VM VirtualBox Unspecified Vulnerability (Windows)");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_win.nasl");
  script_require_keys("Oracle/VirtualBox/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1025805");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpujuly2011-313328.html");
  exit(0);
}


include("version_func.inc");

## Get version from KB
version = get_kb_item("Oracle/VirtualBox/Win/Ver");
if(version)
{
  ## Check for Oracle VM VirtualBox version 4.0
  if(version_is_equal(version:version, test_version:"4.0.0")){
    security_message(0);
  }
}
