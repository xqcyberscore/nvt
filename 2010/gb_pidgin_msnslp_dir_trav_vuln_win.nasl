###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pidgin_msnslp_dir_trav_vuln_win.nasl 8228 2017-12-22 07:29:52Z teissa $
#
# Pidgin MSN Custom Smileys File Disclosure Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_solution = "Apply the patch or upgrade to Pidgin version 2.6.5
  http://pidgin.im/download
  http://developer.pidgin.im/viewmtn/revision/info/c64a1adc8bda2b4aeaae1f273541afbc4f71b810

  *****
  NOTE: Please ignore this warning if the patch is already applied.
  *****";

tag_impact = "Attackers can exploit this issue to gain knowledge of sensitive information
  via directory traversal attacks.
  Impact Level: Application";
tag_affected = "Pidgin version prior to 2.6.4 on Windows.";
tag_insight = "This issue is due to an error in 'slp.c' within the 'MSN protocol plugin'
  in 'libpurple' when processing application/x-msnmsgrp2p MSN emoticon (aka custom
  smiley) request.";
tag_summary = "This host has Pidgin installed and is prone to File Disclosure
  vulnerability";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800421");
  script_version("$Revision: 8228 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-22 08:29:52 +0100 (Fri, 22 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-01-16 12:13:24 +0100 (Sat, 16 Jan 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-0013");
  script_name("Pidgin MSN Custom Smileys File Disclosure Vulnerability (Windows)");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/37953/");
  script_xref(name : "URL" , value : "http://www.pidgin.im/news/security/?id=42");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3662");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_pidgin_detect_win.nasl");
  script_require_keys("Pidgin/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

pidginVer = get_kb_item("Pidgin/Win/Ver");
if(pidginVer != NULL)
{
  if(version_is_less(version:pidginVer, test_version:"2.6.5")){
    security_message(0);
  }
}
