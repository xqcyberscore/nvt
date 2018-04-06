###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_truncation_dialog_code_exec_vuln_lin.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Opera Truncated Dialogs Code Execution Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will let the attacker execute the code and perform
  other unwanted actions.
  Impact Level: System/Application";

tag_affected = "Opera version before 11.67 and 12.x before 12.02 on Linux";
tag_insight = "An error in handling of truncated dialogs, can be used to cause the user
  to download and run executables unexpectedly or perform other unwanted
  actions.";
tag_solution = "Upgrade to Opera version 11.67 or 12.02
  For updates refer to http://www.opera.com/";
tag_summary = "The host is installed with Opera and is prone to code execution
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803148");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2012-6460");
  script_bugtraq_id(55301);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-01-07 16:22:46 +0530 (Mon, 07 Jan 2013)");
  script_name("Opera Truncated Dialogs Code Execution Vulnerability (Linux)");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/1028/");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/unified/1202/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_opera_detection_linux_900037.nasl",
                      "ssh_authorization_init.nasl");
  script_require_keys("Opera/Linux/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
operaVer = NULL;

## Get the version
operaVer = get_kb_item("Opera/Linux/Version");
if(!operaVer){
  exit(0);
}

## Check for opera versions prior to 11.67 and 12.x before 12.02
if(version_is_less(version:operaVer, test_version:"11.67") ||
   version_in_range(version:operaVer, test_version:"12.0",  test_version2:"12.01")){
  security_message(0);
}
