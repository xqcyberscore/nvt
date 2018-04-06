###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pidgin_libpurple_cipher_api_info_disc_vuln_win.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Pidgin 'Libpurple' Cipher API Information Disclosure Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attacker to gain sensitive information.
  Impact Level: Application";
tag_affected = "Pidgin version prior 2.7.10 on Windows";
tag_insight = "The flaw is due to the 'md5_uninit()', 'md4_uninit()', 'des_uninit()',
  'des3_uninit()', 'rc4_uninit()', and 'purple_cipher_context_destroy()'
  functions in libpurple/cipher.c not properly clearing certain sensitive
  structures, which can lead to potentially sensitive information disclosure
  remaining in memory.";
tag_solution = "Upgrade to Pidgin version 2.7.10 or later,
  For updates refer to http://pidgin.im/download";
tag_summary = "This host is installed with Pidgin and is prone to information
  disclosure vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802935");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2011-4922");
  script_bugtraq_id(46307);
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-08-17 17:21:39 +0530 (Fri, 17 Aug 2012)");
  script_name("Pidgin 'Libpurple' Cipher API Information Disclosure Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43271/");
  script_xref(name : "URL" , value : "http://www.pidgin.im/news/security/?id=50");
  script_xref(name : "URL" , value : "http://openwall.com/lists/oss-security/2012/01/04/13");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
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

## Variable initialization
pidginVer = "";

pidginVer = get_kb_item("Pidgin/Win/Ver");
if(pidginVer)
{
  if(version_is_less(version:pidginVer, test_version:"2.7.10")){
    security_message(0);
  }
}
