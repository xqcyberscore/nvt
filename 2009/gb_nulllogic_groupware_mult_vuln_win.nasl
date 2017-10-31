###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nulllogic_groupware_mult_vuln_win.nasl 7573 2017-10-26 09:18:50Z cfischer $
#
# NullLogic Groupware Multiple Vulnerabilities
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

tag_impact = "Attackers can exploit this issue to execute arbitrary SQL
quries in the context of affected application, and can cause buffer overflow
or denial of service.

Impact Level: Application";

tag_affected = "NullLogic Groupware 1.2.7 and prior on all platforms.";

tag_insight = "Multiple flaws occur because,
 - The 'auth_checkpass' function in the login page does not validate the input
   passed into the username parameter.

 - An error in the 'fmessagelist' function in the forum module when processing
   a group name containing a non-numeric string or is an empty string.

 - Multiple stack-based buffer overflows occurs in the 'pgsqlQuery' function
   while processing malicious input to POP3, SMTP or web component that
   triggers a long SQL query when PostgreSQL is used.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is installed with NullLogic Groupware and is prone to
multiple vulnerabilities.";

if(description)
{
  script_id(800906);
  script_version("$Revision: 7573 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 11:18:50 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2009-07-18 09:37:41 +0200 (Sat, 18 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2354", "CVE-2009-2355", "CVE-2009-2356");
  script_bugtraq_id(35606);
  script_name("NullLogic Groupware Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/51591");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/51592");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/51593");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1817");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/504737/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_nulllogic_groupware_detect_win.nasl");
  script_require_keys("NullLogic-Groupware/Ver");
  script_require_ports("Services/www", 4110);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

nullgrpVer = get_kb_item("NullLogic-Groupware/Ver");
if(nullgrpVer == NULL){
  exit(0);
}

# Check for NullLogic Groupware version <= 1.2.7
if(version_is_less_equal(version:nullgrpVer, test_version:"1.2.7")){
  security_message(port:0);
}
