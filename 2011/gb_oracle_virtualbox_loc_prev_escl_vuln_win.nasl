###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_virtualbox_loc_prev_escl_vuln_win.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Oracle VM VirtualBox Extensions Local Privilege Escalation Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_solution = "Apply the patch from below link,
  http://www.oracle.com/technetwork/topics/security/cpujan2011-194091.html

  *****
  NOTE: Ignore this warning, if above mentioned workaround is manually applied.
  *****";

tag_impact = "Successful exploitation will let the local users to gain escalated privileges.
  Impact Level: Application.";
tag_affected = "Oracle VirtualBox version 4.0";
tag_insight = "The flaw is caused by an unspecified error related to various extensions,
  which could allow local authenticated attackers to gain elevated privileges.";
tag_summary = "This host is installed with Oracle VirtualBox and is local privilege
  escalation Vulnerability vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801578");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-01-27 07:47:27 +0100 (Thu, 27 Jan 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2010-4414");
  script_bugtraq_id(45876);
  script_name("Oracle VM VirtualBox Extensions Local Privilege Escalation Vulnerability");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/42985");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0152");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_win.nasl");
  script_require_keys("Oracle/VirtualBox/Win/Ver");
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

# Check for product Oracle VirtuaBox
vmVer = get_kb_item("Oracle/VirtualBox/Win/Ver");
if(vmVer)
{
  if(version_is_equal(version:vmVer, test_version:"4.0")){
    security_message(0);
  }
}
