###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_ty_bof_vuln_lin.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# VLC Media Player TY Processing BOF Vulnerability (Linux)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
###############################################################################

tag_solution = "Upgrade to Version 0.9.5, or
  Apply the available patch from below link,
  http://git.videolan.org/?p=vlc.git;a=commitdiff;h=26d92b87bba99b5ea2e17b7eaa39c462d65e9133#patch1

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation allows attackers to execute arbitrary code
  by tricking a user into opening a specially crafted TY file or can even
  crash an affected application.
  Impact Level: Application";
tag_affected = "VLC media player 0.9.0 through 0.9.4 on Linux (Any).";
tag_insight = "The flaw is due to a boundary error while parsing the header of an
  invalid TY file.";
tag_summary = "This host is installed with VLC Media Player and is prone to
  Buffer Overflow Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800117");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-10-22 15:17:54 +0200 (Wed, 22 Oct 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-4654", "CVE-2008-4686");
  script_bugtraq_id(31813);
  script_name("VLC Media Player TY Processing BOF Vulnerability (Linux)");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/32339/");
  script_xref(name : "URL" , value : "http://www.videolan.org/security/sa0809.html");
  script_xref(name : "URL" , value : "http://www.trapkit.de/advisories/TKADV2008-010.txt");
  script_xref(name : "URL" , value : "http://www.frsirt.com/english/advisories/2008/2856");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("gather-package-list.nasl");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

vlcBinPath = find_bin(prog_name:"vlc", sock:sock);

foreach binPath (vlcBinPath)
{
  if( chomp(binPath) == "" ) continue;
  vlcVer = get_bin_version(full_prog_name:chomp(binPath), version_argv:"--version",
                           ver_pattern:"ersion ([0-9.]+[a-z]?)", sock:sock);
  if(vlcVer)
  {
    # Check for VLC Media Player Version 0.9.0 - 0.9.4
    if(version_in_range(version:vlcVer[1],
                        test_version:"0.9.0", test_version2:"0.9.4")){
      security_message(0);
    }
    ssh_close_connection();
    exit(0);
  }
}
ssh_close_connection();
