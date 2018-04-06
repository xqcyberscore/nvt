###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cscope_putstring_mult_bof_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Cscope putstring Multiple Buffer Overflow vulnerability.
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code or can cause stack based buffer overflows.
  Impact Level: Application";
tag_affected = "Cscope version prior to 15.6";
tag_insight = "Error exists when application fails to perform adequate boundary checks in
  putstring function in find.c via a long function name or symbol in a source
  code file.";
tag_solution = "Upgrade to Cscope version 15.6
  http://sourceforge.net/projects/cscope";
tag_summary = "This host has installed Cscope and is prone to Multiple Buffer
  Overflow vulnerability";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800615");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1577");
  script_name("Cscope putstring Multiple Buffer Overflow vulnerability");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1238");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=499174");
  script_xref(name : "URL" , value : "http://cscope.cvs.sourceforge.net/viewvc/cscope/cscope/src/find.c?view=log#rev1.19");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_cscope_detect.nasl");
  script_require_keys("Cscope/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

cscopeVer = get_kb_item("Cscope/Ver");
if(!cscopeVer){
  exit(0);
}

if(version_is_less(version:cscopeVer, test_version:"15.6")){
  security_message(0);
}
