###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fathftp_client_mult_bof_vuln.nasl 8244 2017-12-25 07:29:28Z teissa $
#
# FathFTP ActiveX Control Multiple Buffer Overflow Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

Impact Level: Application.";

tag_affected = "FathFTP version 1.7";

tag_insight = "The flaws are due to errors in the handling of 'GetFromURL'
member and long argument to the 'RasIsConnected' method, which allow remote
attackers to execute arbitrary code.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with FathFTP and is prone to multiple
buffer overflow vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801379");
  script_version("$Revision: 8244 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-25 08:29:28 +0100 (Mon, 25 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-07-16 19:44:55 +0200 (Fri, 16 Jul 2010)");
  script_cve_id("CVE-2010-2701");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FathFTP ActiveX Control Multiple Buffer Overflow Vulnerabilities");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/60200");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14269/");

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

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FathFTP component_is1";
if(!registry_key_exists(key:key)){
  exit(0);
}

## Check for  FathFTP DisplayName
fftpName = registry_get_sz(key:key, item:"DisplayName");
if("FathFTP" >< fftpName)
{
  fftpVer = eregmatch(pattern:"version ([0-9.]+)", string:fftpName);
  if(fftpVer[1])
  {
    ## Check for the FathFTP version equal to 1.7
    if(version_is_equal(version:fftpVer[1], test_version:"1.7")){
      security_message(0);
    }
  }
}
