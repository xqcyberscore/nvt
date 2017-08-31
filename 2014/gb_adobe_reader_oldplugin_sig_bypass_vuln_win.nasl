###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_oldplugin_sig_bypass_vuln_win.nasl 6759 2017-07-19 09:56:33Z teissa $
#
# Adobe Reader Old Plugin Signature Bypass Vulnerability (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804627");
  script_version("$Revision: 6759 $");
  script_cve_id("CVE-2003-0142");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-19 11:56:33 +0200 (Wed, 19 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-06-05 10:39:40 +0530 (Thu, 05 Jun 2014)");
  script_name("Adobe Reader Old Plugin Signature Bypass Vulnerability (Windows)");

  tag_summary =
"This host is installed with Adobe Reader and is prone to plugin signature
bypass vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaw is due to error that plug-ins with signatures used for older
versions of Acrobat can also be loaded.";

 tag_impact =
"Successful exploitation will allow attacker to submit a modified plug-in to
bypass signature checks and execute malicious code on the system.

Impact Level: System/Application";

  tag_affected =
"Adobe Reader 6.x version on Windows.";

  tag_solution =
"No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/689835");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/328224");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_old_adobe_reader_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader-Old/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
readerVer = "";

## Get Reader Version
if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(readerVer =~ "^(6)\.")
{
  security_message(0);
  exit(0);
}
