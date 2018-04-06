###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_powerpoint_code_exec_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Microsoft PowerPoint File Parsing Remote Code Execution Vulnerability (967340)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Modified to reflect MS09-017 (Sharath S, 2009-05-13 )
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will let the attacker execute arbitrary codes, and can
  cause Memory Corruption, Integer Overflow and other attacks in the context of
  the application through crafting malicious codes inside a powerpoint file.
  Impact Level: System";
tag_affected = "MS PowerPoint 2000 Service Pack 3 and prior
  MS PowerPoint 2002 Service Pack 3 and prior
  MS PowerPoint 2003 Service Pack 3 and prior
  MS PowerPoint 2007 Service Pack 2 and prior
  MS PowerPoint Viewer 2003/2007";
tag_insight = "For more information about vulnerabilities on PowerPoint, go through the links
  mentioned in references.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/Bulletin/MS09-017.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS09-017.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800382");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-04-07 07:29:53 +0200 (Tue, 07 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0556", "CVE-2009-0220", "CVE-2009-0221", "CVE-2009-0222",
                "CVE-2009-0223", "CVE-2009-0224", "CVE-2009-0225", "CVE-2009-0226",
                "CVE-2009-0227", "CVE-2009-1128", "CVE-2009-1129", "CVE-2009-1130",
                "CVE-2009-1131", "CVE-2009-1137", "CVE-2009-0202");
  script_bugtraq_id(34351, 34833, 34835, 34831, 34834, 34879, 34880, 34881, 34882,
                    34837, 34839, 34840, 34841, 34876, 35275);
  script_name("Microsoft PowerPoint File Parsing Remote Code Execution Vulnerability (967340)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35184");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/967340");
  script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2009-29");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/503451");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_office_detection_900025.nasl",
                      "secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver", "SMB/Office/PowerPnt/Version");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

if(get_kb_item("MS/Office/Ver") =~ "^(9|10|11|12)\..*")
{
  # Grep for MS Office PowerPoint Version < (9.0.0.8978, 10.0.6853.0 and
  # 11.0.8307.0, 12.0.6500.5000)
  ppVer = get_kb_item("SMB/Office/PowerPnt/Version");
  if(ppVer != NULL)
  {
    if(version_in_range(version:ppVer, test_version:"9.0",
                        test_version2:"9.0.0.8977") ||
       version_in_range(version:ppVer, test_version:"10.0",
                        test_version2:"10.0.6852.0")||
       version_in_range(version:ppVer, test_version:"11.0",
                        test_version2:"11.0.8306.0")||
       version_in_range(version:ppVer, test_version:"12.0",
                        test_version2:"12.0.6500.4999")){
      security_message(0);
      exit(0);
    }
  }
}

# Check for Office Power Point Version 2007 with compatiability pack
if((get_kb_item("SMB/Office/PowerPnt/Version") =~ "^(12)\..*") ||
    get_kb_item("SMB/Office/PPView/Version"))
{
  ppcnvVer = get_kb_item("SMB/Office/PowerPntCnv/Version");
  if(ppcnvVer != NULL)
 {
    # Check for Power Point Converter 2007 version 12.0 < 12.0.6500.5000
    if(version_in_range(version:ppcnvVer, test_version:"12.0",
                        test_version2:"12.0.6500.4999")){
      security_message(0);
      exit(0);
    }
  }
}

# Check for Power Point Viewer 2003 version 11.0 < 11.0.8305.0
# or Power Point Viewer 2007 version 12.0 < 12.0.6502.5000
ppviewVer = get_kb_item("SMB/Office/PPView/Version");
if(ppviewVer != NULL)
{
  if(version_in_range(version:ppviewVer, test_version:"11.0",
                      test_version2:"11.0.8304.0") ||
     version_in_range(version:ppviewVer, test_version:"12.0",
                      test_version2:"12.0.6502.4999")){
    security_message(0);
  }
}
