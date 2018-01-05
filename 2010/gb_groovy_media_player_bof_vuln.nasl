###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_groovy_media_player_bof_vuln.nasl 8274 2018-01-03 07:28:17Z teissa $
#
# Groovy Media Player '.m3u' File Remote Stack Buffer Overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allows remote attackers to cause a
denial of service or possibly execute arbitrary code.

Impact Level: System/Application";

tag_affected = "Groovy Media Player 1.1.0";

tag_insight = "The flaw is caused by improper bounds checking when parsing
malicious '.M3U' files.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Groovy Media Player and is prone to
buffer overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801405");
  script_version("$Revision: 8274 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-03 08:28:17 +0100 (Wed, 03 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-07-16 19:44:55 +0200 (Fri, 16 Jul 2010)");
  script_cve_id("CVE-2009-4931");
  script_bugtraq_id(34621);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Groovy Media Player '.m3u' File Remote Stack Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/395659.php");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/49965");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
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

if(!registry_key_exists(key:"SOFTWARE\Groovy Media Player")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" +
            "\Groovy Media Player";
if(!registry_key_exists(key:key)){
  exit(0);
}

## Check for Groovy Media Player DisplayName
gmpName = registry_get_sz(key:key, item:"DisplayName");

if("Groovy Media Player" >< gmpName)
{
  ## Get the version from registry key
  gmpVer = registry_get_sz(key:key, item:"DisplayVersion");
  if(gmpVer != NULL)
  {
    ## Check for the Groovy Media Player version equal to '1.1.0'
    if(version_is_equal(version:gmpVer, test_version:"1.1.0")){
        security_message(0);
    }
  }
}
