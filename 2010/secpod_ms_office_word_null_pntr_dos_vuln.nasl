###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_office_word_null_pntr_dos_vuln.nasl 8314 2018-01-08 08:01:01Z teissa $
#
# Microsoft Word 2003 'MSO.dll' Null Pointer Dereference Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 secpod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow remote attackers to cause a
denial of service (NULL pointer dereference and multiple-instance application
crash).

Impact Level: Application";

tag_affected = "Microsoft Office Word 2003 sp3 on Windows.";

tag_insight = "The flaw is due to error in 'MSO.dll' library which fails to handle
the special crafted buffer in a file.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Microsoft Word and is prone to
null pointer dereference vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902250");
  script_version("$Revision: 8314 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-08 09:01:01 +0100 (Mon, 08 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-09-23 08:13:58 +0200 (Thu, 23 Sep 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-3200");
  script_name("Microsoft Word 2003 'MSO.dll' Null Pointer Dereference Vulnerability");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2010/Sep/100");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/513679/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver", "SMB/Office/Word/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Check for the office installation
if(egrep(pattern:"^11\..*", string:get_kb_item("MS/Office/Ver")))
{
  ## check for the Office word installation
  wordVer = get_kb_item("SMB/Office/Word/Version");
  if(!wordVer){
    exit(0);
  }

  # Check for the vulnerable product version
  if(version_in_range(version:wordVer, test_version:"11", test_version2:"11.8326.11.8324"))
  {
    ## Get the path of vulnerable file path
    offPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"CommonFilesDir");
    if(offPath)
    {
      offPath += "\Microsoft Shared\OFFICE11\MSO.DLL";
      share = ereg_replace(pattern:"([A-Za-z]):.*", replace:"\1$", string:offPath);
      file = ereg_replace(pattern:"[A-Za-z]:(.*)", replace:"\1", string:offPath);

      ## Confirm the vulnerable file exists
      dllVer = GetVer(file:file, share:share);
      if(dllVer){
        security_message(0);
      }
    }
  }
}
