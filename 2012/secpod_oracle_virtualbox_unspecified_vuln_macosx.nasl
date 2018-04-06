###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_oracle_virtualbox_unspecified_vuln_macosx.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Oracle VM VirtualBox Unspecified Vulnerability (MAC OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  http://www.oracle.com/technetwork/topics/security/cpujan2012-366304.html

  *****
  NOTE: Ignore this warning, if above mentioned workaround is manually applied.
  *****";

tag_impact = "Successful exploitation allows local users to affect confidentiality,
  integrity and availability via unknown vectors.
  Impact Level: Application";
tag_affected = "Oracle VM VirtualBox version 4.1";
tag_insight = "The flaw is due to unspecified errors related to 'Shared Folders'
  sub component.";
tag_summary = "This host is installed with Oracle VM VirtualBox and is prone to
  unspecified vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902789");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-0111");
  script_bugtraq_id(51465);
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-01-24 11:43:28 +0530 (Tue, 24 Jan 2012)");
  script_name("Oracle VM VirtualBox Unspecified Vulnerability (MAC OS X)");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/47626/");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1026531");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpujan2012-366304.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("General");
  script_dependencies("secpod_oracle_virtualbox_detect_macosx.nasl");
  script_require_keys("Oracle/VirtualBox/MacOSX/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Get version from KB
version = get_kb_item("Oracle/VirtualBox/MacOSX/Version");
if(version)
{
  ## Check for Oracle VM VirtualBox version 4.1
  if(version_is_equal(version:version, test_version:"4.1")){
    security_message(0);
  }
}
