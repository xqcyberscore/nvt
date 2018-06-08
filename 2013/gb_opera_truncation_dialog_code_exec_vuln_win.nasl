###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_truncation_dialog_code_exec_vuln_win.nasl 10137 2018-06-08 12:38:04Z asteins $
#
# Opera Truncated Dialogs Code Execution Vulnerability (Windows)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803147");
  script_version("$Revision: 10137 $");
  script_cve_id("CVE-2012-6460");
  script_bugtraq_id(55301);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-06-08 14:38:04 +0200 (Fri, 08 Jun 2018) $");
  script_tag(name:"creation_date", value:"2013-01-07 16:22:46 +0530 (Mon, 07 Jan 2013)");
  script_name("Opera Truncated Dialogs Code Execution Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/1028/");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/unified/1202/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_opera_detect_portable_win.nasl");
  script_require_keys("Opera/Win/Version");
  script_tag(name : "impact" , value : "Successful exploitation will let the attacker execute the code and perform
  other unwanted actions.
  Impact Level: System/Application");
  script_tag(name : "affected" , value : "Opera version before 11.67 and 12.x before 12.02 on Windows");
  script_tag(name : "insight" , value : "An error in handling of truncated dialogs, can be used to cause the user
  to download and run executables unexpectedly or perform other unwanted
  actions.");
  script_tag(name : "solution" , value : "Upgrade to Opera version 11.67 or 12.02
  For updates refer to http://www.opera.com/");
  script_tag(name : "summary" , value : "The host is installed with Opera and is prone to code execution
  vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

operaVer = "";

operaVer = get_kb_item("Opera/Win/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"11.67") ||
   version_in_range(version:operaVer, test_version:"12.0",  test_version2:"12.01")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
