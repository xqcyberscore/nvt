###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_visio_viewer_ms13-023.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Microsoft Visio Viewer Remote Code Execution Vulnerability (2801261)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code.
  Impact Level: System/Application";

tag_affected = "Microsoft Visio Viewer 2010 Service Pack 1 and prior";
tag_insight = "The flaw is caused by a type confusion error when handling Tree objects
  and can be exploited via a specially crafted Visio file.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms13-023";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS13-023.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902957");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-0079");
  script_bugtraq_id(58369);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-03-13 13:58:19 +0530 (Wed, 13 Mar 2013)");
  script_name("Microsoft Visio Viewer Remote Code Execution Vulnerability (2801261)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52550");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2687505");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1028276");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/MS13-023");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/VisioViewer/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

## Variable Initialization
vvVer = "";

## Get the KB for visio viewer 2010 (14.0.6116.5000)
vvVer = get_kb_item("SMB/Office/VisioViewer/Ver");
if(!vvVer){
  exit(0);
}

if(vvVer && vvVer =~ "^14\.")
{
  if(version_in_range(version:vvVer, test_version:"14.0", test_version2:"14.0.6116.4999")){
    security_message(0);
  }
}
