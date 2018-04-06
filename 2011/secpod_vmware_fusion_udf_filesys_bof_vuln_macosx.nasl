###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_vmware_fusion_udf_filesys_bof_vuln_macosx.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# VMware Fusion UDF File Systems Buffer Overflow Vulnerability (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_impact = "Successful exploitation will allow attacker to execution of arbitrary code.
  Impact Level: System/Application";
tag_solution = "Upgrade to Vmware Fusion version 3.1.3 or later
  For Upgrades refer, http://www.vmware.com/security/advisories/VMSA-2011-0011.html";

tag_affected = "Vmware Fusion 3.1.0 before 3.1.3";
tag_insight = "The flaw is due to an error when handling UDF filesystem images. This can be
  exploited to cause a buffer overflow via a specially crafted ISO image file.";
tag_summary = "The host is installed with VMWare Fusion and are prone to
  buffer overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902634");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2011-3868");
  script_bugtraq_id(49942);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-11-17 17:54:28 +0530 (Thu, 17 Nov 2011)");
  script_name("VMware Fusion UDF File Systems Buffer Overflow Vulnerability (Mac OS X)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46241");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id?1026139");
  script_xref(name : "URL" , value : "http://www.vmware.com/security/advisories/VMSA-2011-0011.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_vmware_fusion_detect_macosx.nasl");
  script_require_keys("VMware/Fusion/MacOSX/Version");
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

if(!get_kb_item("VMware/Fusion/MacOSX/Version")){
  exit(0);
}

# Check for VMware Fusion
vmfusionVer = get_kb_item("VMware/Fusion/MacOSX/Version");
if(vmfusionVer != NULL )
{
  if(version_in_range(version:vmfusionVer, test_version:"3.1.0", test_version2:"3.1.2")){
    security_message(0);
  }
}
