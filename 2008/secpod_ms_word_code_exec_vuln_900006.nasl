##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_word_code_exec_vuln_900006.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: Microsoft Word Could Allow Remote Code Execution Vulnerability
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

tag_impact = "Remote attacker could exploit by persuading victim to open a crafted
 documents to corrupt memory and cause the application to crash, and also allow
 to execute arbitrary code with the system privileges of the victim.
 Impact Level : System";

tag_solution = "Run Windows Update and update the listed hotfixes or download and
 update mentioned hotfixes in the advisory from the below link.
 http://www.microsoft.com/technet/security/bulletin/ms08-042.mspx";

tag_affected = "Microsoft Word 2002 (XP) with SP3 on Windows (All).
 Microsoft Word 2003 with SP3 on Windows (All).";

tag_insight = "Flaw is due to an error within the handling of malformed/crafted MS Word documents.";


tag_summary = "This host is installed with Microsoft Office (with MS Word), which
 is prone to remote code execution vulnerability.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.900006");
 script_version("$Revision: 9349 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2008-08-19 14:38:55 +0200 (Tue, 19 Aug 2008)");
 script_bugtraq_id(30124);
 script_cve_id("CVE-2008-2244");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_category(ACT_GATHER_INFO);
 script_family("Windows");
 script_name("Microsoft Word Could Allow Remote Code Execution Vulnerability");

 script_dependencies("secpod_reg_enum.nasl", "secpod_office_products_version_900032.nasl",
		     "secpod_ms_office_detection_900025.nasl");
 script_mandatory_keys("MS/Office/Ver", "SMB/Office/Word/Version");
 script_xref(name : "URL" , value : "http://secunia.com/advisories/30975");
 script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/43663");
 script_xref(name : "URL" , value : "http://www.frsirt.com/english/advisories/2008/2028");
 script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/advisory/953635.mspx");
 script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms08-042.mspx");
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "affected" , value : tag_affected);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "impact" , value : tag_impact);
 script_tag(name:"qod_type", value:"registry");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}


include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(egrep(pattern:"^(10|11)\..*", string:get_kb_item("MS/Office/Ver")))
{
  # Grep for version < (10.0.6846 - MS Word 2002 SP3 & 11.0.8227.0 - MS Word 2003 SP3)
  wordVer = get_kb_item("SMB/Office/Word/Version");
  if(!wordVer){
    exit(0);
  }

  if(version_in_range(version:wordVer, test_version:"10.0",
                      test_version2:"10.0.6845")){
    security_message(0);
  }
  else if(version_in_range(version:wordVer, test_version:"11.0",
                           test_version2:"11.0.8226")){
    security_message(0);
  }
}
