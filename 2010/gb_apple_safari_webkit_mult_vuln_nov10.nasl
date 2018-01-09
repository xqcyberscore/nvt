###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_webkit_mult_vuln_nov10.nasl 8296 2018-01-05 07:28:01Z teissa $
#
# Apple Safari Webkit Multiple Vulnerabilities - Nov10
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation will allow attacker to bypass certain security
  restrictions, conduct spoofing attacks, or compromise a user's system.
  Impact Level: Application";
tag_affected = "Apple Safari versions prior to 5.0.3";
tag_insight = "For more information about vulnerabilities, refer the links mentioned in
  references.";
tag_solution = "Upgrade to Apple Safari version 5.0.3 or later,
  For updates refer to http://www.apple.com/support/downloads/";
tag_summary = "The host is installed with Apple Safari web browser and is prone
  to multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801641");
  script_version("$Revision: 8296 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-05 08:28:01 +0100 (Fri, 05 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-11-23 14:41:37 +0100 (Tue, 23 Nov 2010)");
  script_cve_id("CVE-2010-3803", "CVE-2010-3804", "CVE-2010-3805", "CVE-2010-3808",
                "CVE-2010-3809", "CVE-2010-3810", "CVE-2010-3811", "CVE-2010-3812",
                "CVE-2010-3813", "CVE-2010-3816", "CVE-2010-3817", "CVE-2010-3818",
                "CVE-2010-3819", "CVE-2010-3820", "CVE-2010-3821", "CVE-2010-3822",
                "CVE-2010-3823", "CVE-2010-3824", "CVE-2010-3826");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Apple Safari Webkit Multiple Vulnerabilities - Nov10");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT4455");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42264/");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2010//Nov/msg00002.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_require_keys("AppleSafari/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

safVer = get_kb_item("AppleSafari/Version");
if(!safVer){
  exit(0);
}

## Grep for Apple Safari Versions prior to 5.0.3 (5.33.19.4)
if(version_is_less(version:safVer, test_version:"5.33.19.4")){
  security_message(0);
}
