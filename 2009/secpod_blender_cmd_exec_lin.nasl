###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_blender_cmd_exec_lin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Blender .blend File Command Execution Vulnerability
#
# Authors:
# Maneesh KB <kmaneesh@secpod.com>
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary
commands by sending a specially crafted .blend file that contains Python
statements in the onLoad action of a ScriptLink SDNA.

Impact Level: Application";

tag_affected = "Blender 2.49b, 2.40, 2.35a, 2.34 and prior.";

tag_insight = "This flaw is generated because Blender allows .blend project
files to be modified to execute arbitrary commands without user intervention
by design.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with blender and is prone to Remote
Command Execution Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900252");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-11-20 06:52:52 +0100 (Fri, 20 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3850");
  script_bugtraq_id(36838);
  script_name("Blender .blend File Command Execution Vulnerability");
  script_xref(name : "URL" , value : "http://www.coresecurity.com/content/blender-scripting-injection");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("General");
  script_dependencies("secpod_blender_detect_lin.nasl");
  script_require_keys("Blender/Lin/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"executable_version");
  exit(0);
}


include("version_func.inc");

blendVer = get_kb_item("Blender/Lin/Ver");
if(!blendVer){
  exit(0);
}

#Check if version is equal to 2.49b(2.49.2), 2.40, 2.35a(2.35.1), 2.34 or prior
if(version_is_equal(version:blendVer, test_version:"2.49.2")||
   version_is_equal(version:blendVer, test_version:"2.40")  ||
   version_is_equal(version:blendVer, test_version:"2.35.1")||
   version_is_less_equal(version:blendVer, test_version:"2.34")){
  security_message(0);
}
