###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_unspecified_vuln.nasl 8438 2018-01-16 17:38:23Z teissa $
#
# Microsoft Internet Explorer Unspecified vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Impact is currently unknown.

Impact Level: Application";

tag_affected = "Microsoft Internet Explorer 7.0 Windows XP SP3 and prior.
Microsoft Internet Explorer 7.0 Windows Server 2K3 SP2 and prior.";

tag_insight = "The flaw exists due to the error in processing of 'XML'
document that references a crafted web site via the 'SRC' attribute of an
image element.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Microsoft Internet Explorer and is
prone to unspecified vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800742");
  script_version("$Revision: 8438 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-16 18:38:23 +0100 (Tue, 16 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-04-06 08:47:09 +0200 (Tue, 06 Apr 2010)");
  script_cve_id("CVE-2010-1175");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Internet Explorer Unspecified vulnerability");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/510280/100/0/threaded");

  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_keys("MS/IE/Version");
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

if(hotfix_check_sp(xp:4, win2003:3) <= 0){
  exit(0);
}

ieVer = get_kb_item("MS/IE/Version");
if(ieVer)
{
  # Check for IE Version 7.x
  if(ieVer =~ "^7\."){
    security_message(0);
  }
}
