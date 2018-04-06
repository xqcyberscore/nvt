###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_aimp_id3_tag_bof_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# AIMP ID3 Tag Buffer Overflow Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated to CVE-2009-3170
# - By Nikita MR <rnikita@secpod.com> On 2009-09-15 #4729
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

tag_impact = "Successful exploitation will allow remote attackers to exploit
arbitrary code in the context of the affected application.

Impact level: Application";

tag_affected = "AIMP2 version 2.5.1.330 and prior.";

tag_insight = "- A boundary check error exists while processing MP3 files with
overly long ID3 tag.
- Stack-based buffer overflow occurs when application fails to handle long
File1 argument in a '.pls' or '.m3u' playlist file.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host has AIMP2 player installed and is prone to Buffer Overflow
vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800591");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-07-07 11:58:41 +0200 (Tue, 07 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1944", "CVE-2009-3170");
  script_name("AIMP ID3 Tag Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35295/");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9561");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8837");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50875");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2530");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_aimp_detect.nasl");
  script_require_keys("AIMP/Ver");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

aimpVer = get_kb_item("AIMP/Ver");

if(aimpVer != NULL)
{
  # Grep for AIMP2 Player 2.5.1.330 and prior
  if(version_is_less_equal(version:aimpVer, test_version:"2.5.1.330")){
    security_message(0);
  }
}
