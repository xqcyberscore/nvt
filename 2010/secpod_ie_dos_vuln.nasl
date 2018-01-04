###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ie_dos_vuln.nasl 8269 2018-01-02 07:28:22Z teissa $
#
# Microsoft Windows '.ani' file Denial of Service vulnerability
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
# You should have receivedreceived a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploits will cause application to crash or become
unresponsive, denying service to legitimate users.

Impact Level: Application";

tag_affected = "Microsoft Windows 2000 SP4 and earlier
  Microsoft Windows XP SP3 and earlier
  Microsoft Windows 2003 SP2 and earlier";

tag_insight = "The flaw is due to improper bounds checking when processing
'.ani' files which can be exploited via crafted '.ani' file to cause the system
to consume an overly large amount of memory and become unresponsive.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host has ANI parser in Microsoft Windows and is prone to
denial of dervice vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902033");
  script_version("$Revision: 8269 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-02 08:28:22 +0100 (Tue, 02 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-03-30 16:15:33 +0200 (Tue, 30 Mar 2010)");
  script_bugtraq_id(38579);
  script_cve_id("CVE-2010-1098");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_name("Microsoft Windows '.ani' file Denial of Service vulnerability");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/56756");
  script_xref(name : "URL" , value : "http://code.google.com/p/skylined/issues/detail?id=3");
  script_xref(name : "URL" , value : "http://skypher.com/index.php/2010/03/08/ani-file-bitmapinfoheader-biclrused-bounds-check-missing/");

  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (c) 2010 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");

## Check for Windows 2000 SP4 and before, Windows XP SP3 and before
## Windows 2003 SP2 and before
if(hotfix_check_sp(win2k:5, xp:4, win2003:3) == 0){
  security_message(0);
}
