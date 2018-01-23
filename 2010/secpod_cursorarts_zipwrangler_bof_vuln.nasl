###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_cursorarts_zipwrangler_bof_vuln.nasl 8485 2018-01-22 07:57:57Z teissa $
#
# CursorArts ZipWrangler 'ZIP Processing' Buffer Overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow remote attackers to execute
arbitrary code with a specially crafted ZIP file.

Impact Level: Application.";

tag_affected = "CursorArts ZipWrangler version 1.20.";

tag_insight = "The flaw exists due to boundary error when processing certain
ZIP files, which leads to stack-based buffer overflow by tricking a user into
opening a specially crafted ZIP file.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with CursorArts ZipWrangler and is prone
to buffer overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902071");
  script_version("$Revision: 8485 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-22 08:57:57 +0100 (Mon, 22 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-06-21 15:32:44 +0200 (Mon, 21 Jun 2010)");
  script_cve_id("CVE-2010-1685");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("CursorArts ZipWrangler 'ZIP Processing' Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39575");
  script_xref(name : "URL" , value : "http://www.corelan.be:8800/index.php/forum/security-advisories/corelan-10-031-zip-wrangler-1-20-buffer-overflow/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" +
         "\ZipWrangler version 1.20_is1";

if(!registry_key_exists(key:key)){
  exit(0);
}

## Check for ZipWrangler DisplayName
zipName = registry_get_sz(key:key, item:"DisplayName");
if("ZipWrangler" >< zipName)
{
  ## Grep the version for ZipWrangler
  zipVer = eregmatch(pattern:" version ([0-9.]+)", string:zipName);
  if(zipVer[1] != NULL)
  {
    ## Check for ZipWrangler version equal to '1.20'
    if(version_is_equal(version:zipVer[1], test_version:"1.20")){
      security_message(0) ;
    }
  }
}
