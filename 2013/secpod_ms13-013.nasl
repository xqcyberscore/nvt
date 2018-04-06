###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-013.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Microsoft FAST Search Server 2010 SharePoint RCE Vulnerabilities (2784242)
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

tag_impact = "Successful exploitation could run arbitrary code in the context of a user
  account with a restricted token.
  Impact Level: System/Application";

tag_affected = "Microsoft FAST Search Server 2010 for SharePoint Service Pack 1";
tag_insight = "The flaws are due to the error in Oracle Outside In libraries, when
  used by the Advanced Filter Pack while parsing specially crafted files.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms13-013";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS13-013.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902949");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2012-3214", "CVE-2012-3217");
  script_bugtraq_id(55977, 55993);
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-02-13 11:28:37 +0530 (Wed, 13 Feb 2013)");
  script_name("Microsoft FAST Search Server 2010 SharePoint RCE Vulnerabilities (2784242)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52136/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2553234");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms13-013");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_fast_search_server_detect.nasl");
  script_mandatory_keys("MS/SharePoint/Install/Path");
  script_require_ports(139, 445);

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
path = "";
dllPath = "";
dllVer = "";

## SharePoint Server 2010
path = get_kb_item("MS/SharePoint/Install/Path");
if(!path){
  exit(0);
}

dllPath = path + "bin";
dllVer = fetch_file_version(sysPath:dllPath,
         file_name:"Vseshr.dll");
if(!dllVer){
  exit(0);
}

if(version_in_range(version:dllVer, test_version:"8.3.7.000", test_version2:"8.3.7.206")){
  security_message(0);
}
