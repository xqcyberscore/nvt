###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms09-030.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Microsoft Office Publisher Remote Code Execution Vulnerability (969516)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could execute arbitrary code on the remote system
  via a specially crafted Publisher file.
  Impact Level: Application";
tag_affected = "Microsoft Office 2007 SP1 and prior
  Microsoft Office Publisher 2007 SP1 and prior";
tag_insight = "The flaw is due to error in calculating object handler data when opening
  files created in older versions of Publisher. This can be exploited to
  corrupt memory and cause an invalid value to be dereferenced as a pointer.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link.
  http://www.microsoft.com/technet/security/bulletin/ms09-030.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS09-030.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900391");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-07-15 20:20:16 +0200 (Wed, 15 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0566");
  script_bugtraq_id(35599);
  script_name("Microsoft Office Publisher Remote Code Execution Vulnerability (969516)");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl", "secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("MS/Office/Ver", "SMB/Office/Publisher/Version");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35779");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/969693");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms09-030.mspx");
  exit(0);
}


include("version_func.inc");

# Check for Office 2007 or 2007 SP1
if(egrep(pattern:"^12\..*", string:get_kb_item("MS/Office/Ver")))
{
  # Grep for Office Publisher Version from KB
  pubVer = get_kb_item("SMB/Office/Publisher/Version");
  if(!pubVer){
    exit(0);
  }

  # Check for Office Publisher 12.0 < 12.0.6501.5000
  if(version_in_range(version:pubVer, test_version:"12.0",
                      test_version2:"12.0.6501.4999")){
    security_message(0);
  }
}
