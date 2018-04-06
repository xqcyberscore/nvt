###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_pidgin_mul_bof_vuln_win.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Pidgin Multiple Buffer Overflow Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploits allow attackers to run arbitrary code, corrupt memory
  and cause cause denial of service.
  Impact Level: Application";
tag_affected = "Pidgin version prior to 2.5.6 on Windows.";
tag_insight = "The multiple flaws are due to,
  - a boundary error in the XMPP SOCKS5 'bytestream' server when initiating
    an outbound XMPP file transfer.
  - a boundary error in the 'decrypt_out()' function while processing
    malicious QQ packet.
  - a boundary error exists in the implementation of the 'PurpleCircBuffer'
    structure and can be exploited via vectors involving  XMPP or Sametime
    protocol.
  - a truncation error in  function 'libpurple/protocols/msn/slplink.c' and
   'libpurple/protocols/msnp9/slplink.c' when processing MSN SLP messages
    with a crafted offset value.";
tag_solution = "Upgrade to version 2.5.6 or later.
  http://pidgin.im/download/";
tag_summary = "This host has installed pidgin and is prone to Multiple Buffer
  Overflow Vulnerabilities";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900664");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-01 09:35:57 +0200 (Mon, 01 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1373", "CVE-2009-1374",
                "CVE-2009-1375", "CVE-2009-1376");
  script_bugtraq_id(35067);
  script_name("Pidgin Multiple Buffer Overflow Vulnerabilities (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35194");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35202");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50680");
  script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2009-1059.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_pidgin_detect_win.nasl");
  script_require_keys("Pidgin/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

pidginVer = get_kb_item("Pidgin/Win/Ver");
if(pidginVer != NULL)
{
  if(version_is_less(version:pidginVer, test_version:"2.5.6")){
    security_message(0);
  }
}
