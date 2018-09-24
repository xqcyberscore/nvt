###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pidgin_mult_vuln_sep09_win.nasl 11554 2018-09-22 15:11:42Z cfischer $
#
# Pidgin Multiple Vulnerabilities - Sep09 (Windows)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800931");
  script_version("$Revision: 11554 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-09-03 16:18:01 +0200 (Thu, 03 Sep 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-3025", "CVE-2009-3026");
  script_name("Pidgin Multiple Vulnerabilities - Sep09 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36384/");
  script_xref(name:"URL", value:"http://pidgin.im/news/security/?id=35");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=542891");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/08/19/2");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_pidgin_detect_win.nasl");
  script_mandatory_keys("Pidgin/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker obtain sensitive information
  by sniffing XMPP sessions and cause application crash.");
  script_tag(name:"affected", value:"Pidgin version 2.6.0 on Windows");
  script_tag(name:"insight", value:"- The application connects to Jabberd servers that are not fully compliant
   with the XMPP specifications without encryption, even if the
   'Require SSL/TLS' setting is configured.

  - An error ocurrs in compililg libpurple while processing malicious links
   received via the Yahoo Messenger protocol.");
  script_tag(name:"solution", value:"Upgrade to Pidgin version 2.6.1
  http://pidgin.im/download");
  script_tag(name:"summary", value:"This host has Pidgin installed and is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

pidginVer = get_kb_item("Pidgin/Win/Ver");

if(pidginVer != NULL)
{
  if(version_is_equal(version:pidginVer, test_version:"2.6.0")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
